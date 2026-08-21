<?php

namespace Webilia\Connect\WordPress;

use RuntimeException;
use Webilia\Connect\Contracts\ConditionalConnectionStorage;
use Webilia\Connect\Contracts\Storage;

final class WordPressStorage implements Storage, ConditionalConnectionStorage
{
    private const CONNECTION_OPTION = 'webilia_connect_connection';
    private const CONNECTION_LOCK_OPTION = 'webilia_connect_connection_lock';
    private const ENCRYPTION_KEY_FILE = '.webilia-connect-key.php';
    private const PENDING_OPTION = 'webilia_connect_pending_requests';
    private const PENDING_LOCK_OPTION = 'webilia_connect_pending_requests_lock';
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

    public function saveConnectionIfCurrent(array $connection, ?string $expectedCredential, ?string $expectedRevision): bool
    {
        return $this->withLock(self::CONNECTION_LOCK_OPTION, function () use ($connection, $expectedCredential, $expectedRevision): bool {
            $current = $this->connection();
            $currentCredential = is_array($current) ? (string) ($current['credential'] ?? '') : null;
            $currentRevision = is_array($current) && isset($current['connection_revision']) ? (string) $current['connection_revision'] : null;
            if ($currentCredential !== $expectedCredential || $currentRevision !== $expectedRevision) {
                return false;
            }

            $this->saveConnection($connection);

            return true;
        });
    }

    public function forgetConnection(): void
    {
        if (! delete_option(self::CONNECTION_OPTION) && get_option(self::CONNECTION_OPTION, null) !== null) {
            throw new RuntimeException('Unable to remove the Webilia connection credential.');
        }
    }

    public function forgetConnectionIfCurrent(string $expectedCredential, ?string $expectedRevision): bool
    {
        return $this->withLock(self::CONNECTION_LOCK_OPTION, function () use ($expectedCredential, $expectedRevision): bool {
            $current = $this->connection();
            if (! is_array($current)
                || ! hash_equals((string) ($current['credential'] ?? ''), $expectedCredential)
                || (isset($current['connection_revision']) ? (string) $current['connection_revision'] : null) !== $expectedRevision) {
                return false;
            }

            $this->forgetConnection();

            return true;
        });
    }

    public function pending(string $state): ?array
    {
        return $this->withLock(self::PENDING_LOCK_OPTION, function () use ($state): ?array {
            $requests = $this->cleanPendingRequests($this->pendingRequests());
            $this->savePendingRequests($requests);
            $value = $requests[$state] ?? null;

            return is_array($value) && hash_equals((string) ($value['state'] ?? ''), $state) ? $value : null;
        });
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

        $this->withLock(self::PENDING_LOCK_OPTION, function () use ($state, $pending): void {
            $requests = $this->cleanPendingRequests($this->pendingRequests());
            $requests[$state] = $pending;
            $this->savePendingRequests($requests);
        });
    }

    public function forgetPending(string $state): void
    {
        $this->withLock(self::PENDING_LOCK_OPTION, function () use ($state): void {
            $requests = $this->cleanPendingRequests($this->pendingRequests());
            unset($requests[$state]);
            $this->savePendingRequests($requests);
        });
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
        $temporaryPath = $path.'.'.bin2hex(random_bytes(12)).'.tmp.php';
        $previousUmask = umask(0077);
        $handle = @fopen($temporaryPath, 'x');
        umask($previousUmask);
        if ($handle === false) {
            throw new RuntimeException('Unable to create the Webilia connection encryption key.');
        }

        if (! $this->privateKeyFile($temporaryPath)) {
            fclose($handle);
            @unlink($temporaryPath);

            throw new RuntimeException('Unable to secure the Webilia connection encryption key.');
        }

        $contents = "<?php\nif (! defined('ABSPATH')) { exit; }\n\nreturn '".base64_encode($key)."';\n";
        $written = fwrite($handle, $contents);
        fclose($handle);
        if ($written !== strlen($contents)) {
            @unlink($temporaryPath);

            throw new RuntimeException('Unable to create the Webilia connection encryption key.');
        }

        if (! @link($temporaryPath, $path)) {
            @unlink($temporaryPath);
            $stored = $this->storedFileKey($path);
            if ($stored !== null) {
                return $stored;
            }

            return $this->createKeyFileWithoutHardLink($path, $contents, $key);
        }

        @unlink($temporaryPath);

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
        if (! $this->privateKeyFile($path)) {
            return null;
        }

        $encoded = include $path;
        $key = is_string($encoded) ? base64_decode($encoded, true) : false;

        return is_string($key) && strlen($key) === 32 ? $key : null;
    }

    private function createKeyFileWithoutHardLink(string $path, string $contents, string $key): string
    {
        $lockPath = $path.'.lock';
        $previousUmask = umask(0077);
        $lock = @fopen($lockPath, 'c');
        umask($previousUmask);
        if ($lock === false || ! flock($lock, LOCK_EX)) {
            if (is_resource($lock)) {
                fclose($lock);
            }

            throw new RuntimeException('Unable to create the Webilia connection encryption key.');
        }

        try {
            $stored = $this->storedFileKey($path);
            if ($stored !== null) {
                return $stored;
            }

            $temporaryPath = $path.'.'.bin2hex(random_bytes(12)).'.tmp.php';
            $previousUmask = umask(0077);
            $handle = @fopen($temporaryPath, 'x');
            umask($previousUmask);
            if ($handle === false || ! $this->privateKeyFile($temporaryPath)) {
                if (is_resource($handle)) {
                    fclose($handle);
                }
                @unlink($temporaryPath);

                throw new RuntimeException('Unable to create the Webilia connection encryption key.');
            }

            $written = fwrite($handle, $contents);
            fclose($handle);
            if ($written !== strlen($contents) || ! @rename($temporaryPath, $path)) {
                @unlink($temporaryPath);

                throw new RuntimeException('Unable to create the Webilia connection encryption key.');
            }

            return $key;
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    private function privateKeyFile(string $path): bool
    {
        clearstatcache(true, $path);
        $permissions = @fileperms($path);

        return is_readable($path) && is_int($permissions) && ($permissions & 0077) === 0;
    }

    private function legacyFileKey(): ?string
    {
        if (! defined('WEBILIA_CONNECT_KEY') || (string) WEBILIA_CONNECT_KEY === '') {
            return null;
        }

        return $this->storedFileKey($this->keyPath());
    }

    /** @return array<string, array<string, mixed>> */
    private function pendingRequests(): array
    {
        $requests = get_option(self::PENDING_OPTION, []);

        return is_array($requests) ? $requests : [];
    }

    /** @param array<string, array<string, mixed>> $requests @return array<string, array<string, mixed>> */
    private function cleanPendingRequests(array $requests): array
    {
        foreach ($requests as $state => $request) {
            if (! is_array($request) || (int) ($request['expires_at'] ?? 0) < time()) {
                unset($requests[$state]);
            }
        }

        return $requests;
    }

    /** @param array<string, array<string, mixed>> $requests */
    private function savePendingRequests(array $requests): void
    {
        if ($requests === []) {
            if (! delete_option(self::PENDING_OPTION) && get_option(self::PENDING_OPTION, null) !== null) {
                throw new RuntimeException('Unable to remove the pending Webilia Connect request.');
            }

            return;
        }

        if (! update_option(self::PENDING_OPTION, $requests, false) && get_option(self::PENDING_OPTION, null) !== $requests) {
            throw new RuntimeException('Unable to save the pending Webilia Connect request.');
        }
    }

    private function authorizationOption(string $key): string
    {
        return self::AUTHORIZATION_PREFIX.md5($key);
    }

    /** @template T @param callable(): T $callback @return T */
    private function withLock(string $option, callable $callback)
    {
        $token = bin2hex(random_bytes(16));
        $deadline = microtime(true) + 2;

        do {
            $lock = ['token' => $token, 'expires_at' => time() + 30];
            if (add_option($option, $lock, '', false)) {
                try {
                    return $callback();
                } finally {
                    $this->deleteLockIfCurrent($option, $lock);
                }
            }

            $lock = get_option($option, null);
            if (is_array($lock) && (int) ($lock['expires_at'] ?? 0) < time()) {
                $this->deleteLockIfCurrent($option, $lock);
            }

            usleep(50000);
        } while (microtime(true) < $deadline);

        throw new RuntimeException('Unable to obtain the Webilia Connect storage lock.');
    }

    /** @param array<string, mixed> $lock */
    private function deleteLockIfCurrent(string $option, array $lock): bool
    {
        global $wpdb;

        if (isset($wpdb) && is_object($wpdb) && isset($wpdb->options) && method_exists($wpdb, 'prepare') && method_exists($wpdb, 'query')) {
            $query = $wpdb->prepare(
                'DELETE FROM '.$wpdb->options.' WHERE option_name = %s AND option_value = %s',
                $option,
                serialize($lock)
            );
            $deleted = $wpdb->query($query);
            if (function_exists('wp_cache_delete')) {
                wp_cache_delete($option, 'options');
            }

            return $deleted === 1;
        }

        return get_option($option, null) === $lock && delete_option($option);
    }
}
