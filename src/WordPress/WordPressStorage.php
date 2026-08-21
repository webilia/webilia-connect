<?php

namespace Webilia\Connect\WordPress;

use RuntimeException;
use Webilia\Connect\Contracts\Storage;

final class WordPressStorage implements Storage
{
    private const CONNECTION_OPTION = 'webilia_connect_connection';
    private const ENCRYPTION_KEY_FILE = '.webilia-connect-key.php';
    private const PENDING_PREFIX = 'webilia_connect_pending_';
    private const AUTHORIZATION_PREFIX = 'webilia_connect_authorization_';

    public function connection(): ?array
    {
        $value = get_option(self::CONNECTION_OPTION, '');
        if (! is_string($value) || $value === '') {
            return null;
        }

        $connection = $this->decrypt($value, $this->key());
        if ($connection !== null) {
            return $connection;
        }

        $legacyKey = $this->legacyFileKey();
        if ($legacyKey === null) {
            return null;
        }

        $connection = $this->decrypt($value, $legacyKey);
        if ($connection === null) {
            return null;
        }

        if (! update_option(self::CONNECTION_OPTION, $this->encrypt($connection), false)) {
            throw new RuntimeException('Unable to migrate the Webilia connection credential.');
        }

        return $connection;
    }

    public function saveConnection(array $connection): void
    {
        if (! update_option(self::CONNECTION_OPTION, $this->encrypt($connection), false)) {
            throw new RuntimeException('Unable to save the Webilia connection credential.');
        }
    }

    public function forgetConnection(): void
    {
        if (! delete_option(self::CONNECTION_OPTION) && get_option(self::CONNECTION_OPTION, null) !== null) {
            throw new RuntimeException('Unable to remove the Webilia connection credential.');
        }
    }

    public function pending(string $state): ?array
    {
        $option = $this->pendingOption($state);
        $value = get_option($option, []);
        if (! is_array($value) || (int) ($value['expires_at'] ?? 0) < time()) {
            if (is_array($value)) {
                $this->forgetPending($state);
            }

            return null;
        }

        return hash_equals((string) ($value['state'] ?? ''), $state) ? $value : null;
    }

    public function savePending(array $pending): void
    {
        $state = (string) ($pending['state'] ?? '');
        if ($state === '') {
            throw new RuntimeException('The pending Webilia Connect request is missing its state.');
        }

        $expiresAt = (int) ($pending['expires_at'] ?? 0);
        $expiration = $expiresAt - time();
        if ($expiration <= 0) {
            throw new RuntimeException('The pending Webilia Connect request has expired.');
        }

        $option = $this->pendingOption($state);
        if (! update_option($option, $pending, false) && get_option($option, null) !== $pending) {
            throw new RuntimeException('Unable to save the pending Webilia Connect request.');
        }
    }

    public function forgetPending(string $state): void
    {
        $option = $this->pendingOption($state);
        if (! delete_option($option) && get_option($option, null) !== null) {
            throw new RuntimeException('Unable to remove the pending Webilia Connect request.');
        }
    }

    public function authorization(string $key): ?array
    {
        $value = get_transient($this->authorizationOption($key));

        return is_array($value) ? $value : null;
    }

    public function saveAuthorization(string $key, array $authorization): void
    {
        $cacheUntil = (int) ($authorization['cache_until'] ?? 0);
        $expiration = $cacheUntil - time();
        if ($expiration <= 0) {
            $this->forgetAuthorization($key);

            return;
        }

        $transient = $this->authorizationOption($key);
        if (! set_transient($transient, $authorization, $expiration) && get_transient($transient) !== $authorization) {
            throw new RuntimeException('Unable to save the cached Webilia Connect authorization.');
        }
    }

    public function forgetAuthorization(string $key): void
    {
        $transient = $this->authorizationOption($key);
        if (! delete_transient($transient) && get_transient($transient) !== false) {
            throw new RuntimeException('Unable to remove the cached Webilia Connect authorization.');
        }
    }

    /** @param array<string, mixed> $payload */
    private function encrypt(array $payload): string
    {
        $iv = random_bytes(12);
        $tag = '';
        $encrypted = openssl_encrypt(
            wp_json_encode($payload),
            'aes-256-gcm',
            $this->key(),
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if (! is_string($encrypted)) {
            throw new RuntimeException('Unable to secure the Webilia connection credential.');
        }

        return base64_encode($iv.$tag.$encrypted);
    }

    /** @return array<string, mixed>|null */
    private function decrypt(string $value, string $key): ?array
    {
        $binary = base64_decode($value, true);
        if ($binary === false || strlen($binary) < 29) {
            return null;
        }

        $iv = substr($binary, 0, 12);
        $tag = substr($binary, 12, 16);
        $ciphertext = substr($binary, 28);
        $json = openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
        $payload = is_string($json) ? json_decode($json, true) : null;

        return is_array($payload) ? $payload : null;
    }

    private function key(): string
    {
        if (defined('WEBILIA_CONNECT_KEY') && (string) WEBILIA_CONNECT_KEY !== '') {
            return hash('sha256', (string) WEBILIA_CONNECT_KEY.':webilia-connect', true);
        }

        $path = $this->keyPath();
        $stored = $this->storedFileKey($path);
        if ($stored !== null) {
            return $stored;
        }

        $key = random_bytes(32);
        $previousUmask = umask(0077);
        $handle = @fopen($path, 'x');
        umask($previousUmask);
        if ($handle === false) {
            $stored = $this->storedFileKey($path);
            if ($stored !== null) {
                return $stored;
            }

            throw new RuntimeException('Unable to create the Webilia connection encryption key.');
        }

        clearstatcache(true, $path);
        $permissions = @fileperms($path);
        if (! is_int($permissions) || ($permissions & 0077) !== 0) {
            fclose($handle);
            @unlink($path);

            throw new RuntimeException('Unable to secure the Webilia connection encryption key.');
        }

        $contents = "<?php\nif (! defined('ABSPATH')) { exit; }\n\nreturn '".base64_encode($key)."';\n";
        $written = fwrite($handle, $contents);
        fclose($handle);
        if ($written !== strlen($contents)) {
            @unlink($path);

            throw new RuntimeException('Unable to create the Webilia connection encryption key.');
        }

        clearstatcache(true, $path);
        if (! @chmod($path, 0600)) {
            @unlink($path);

            throw new RuntimeException('Unable to secure the Webilia connection encryption key.');
        }

        clearstatcache(true, $path);
        $permissions = @fileperms($path);
        if (! is_int($permissions) || ($permissions & 0777) !== 0600) {
            @unlink($path);

            throw new RuntimeException('Unable to secure the Webilia connection encryption key.');
        }

        return $key;
    }

    private function keyPath(): string
    {
        if (! defined('WP_CONTENT_DIR') || ! is_string(WP_CONTENT_DIR) || WP_CONTENT_DIR === '') {
            throw new RuntimeException('Webilia Connect requires a writable WordPress content directory.');
        }

        return rtrim(WP_CONTENT_DIR, '/\\').DIRECTORY_SEPARATOR.self::ENCRYPTION_KEY_FILE;
    }

    private function storedFileKey(string $path): ?string
    {
        clearstatcache(true, $path);
        $permissions = @fileperms($path);
        if (! is_readable($path) || ! is_int($permissions) || ($permissions & 0077) !== 0) {
            return null;
        }

        $encoded = include $path;
        $key = is_string($encoded) ? base64_decode($encoded, true) : false;

        return is_string($key) && strlen($key) === 32 ? $key : null;
    }

    private function legacyFileKey(): ?string
    {
        if (! defined('WEBILIA_CONNECT_KEY') || (string) WEBILIA_CONNECT_KEY === '') {
            return null;
        }

        return $this->storedFileKey($this->keyPath());
    }

    private function pendingOption(string $state): string
    {
        return self::PENDING_PREFIX.hash('sha256', $state);
    }

    private function authorizationOption(string $key): string
    {
        return self::AUTHORIZATION_PREFIX.md5($key);
    }
}
