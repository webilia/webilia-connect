<?php

namespace Webilia\Connect\WordPress;

use RuntimeException;
use Webilia\Connect\Contracts\Storage;

final class WordPressStorage implements Storage
{
    private const CONNECTION_OPTION = 'webilia_connect_connection';
    private const PENDING_PREFIX = 'webilia_connect_pending_';
    private const AUTHORIZATION_PREFIX = 'webilia_connect_authorization_';

    public function connection(): ?array
    {
        $value = get_option(self::CONNECTION_OPTION, '');
        if (! is_string($value) || $value === '') {
            return null;
        }

        return $this->decrypt($value);
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
        $value = get_option($this->pendingOption($state), []);

        return is_array($value) && hash_equals((string) ($value['state'] ?? ''), $state) ? $value : null;
    }

    public function savePending(array $pending): void
    {
        $state = (string) ($pending['state'] ?? '');
        if ($state === '') {
            throw new RuntimeException('The pending Webilia Connect request is missing its state.');
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
        $value = get_option($this->authorizationOption($key), []);

        return is_array($value) ? $value : null;
    }

    public function saveAuthorization(string $key, array $authorization): void
    {
        $option = $this->authorizationOption($key);
        if (! update_option($option, $authorization, false) && get_option($option, null) !== $authorization) {
            throw new RuntimeException('Unable to save the cached Webilia Connect authorization.');
        }
    }

    public function forgetAuthorization(string $key): void
    {
        $option = $this->authorizationOption($key);
        if (! delete_option($option) && get_option($option, null) !== null) {
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
    private function decrypt(string $value): ?array
    {
        $binary = base64_decode($value, true);
        if ($binary === false || strlen($binary) < 29) {
            return null;
        }

        $iv = substr($binary, 0, 12);
        $tag = substr($binary, 12, 16);
        $ciphertext = substr($binary, 28);
        $json = openssl_decrypt($ciphertext, 'aes-256-gcm', $this->key(), OPENSSL_RAW_DATA, $iv, $tag);
        $payload = is_string($json) ? json_decode($json, true) : null;

        return is_array($payload) ? $payload : null;
    }

    private function key(): string
    {
        return hash('sha256', wp_salt('auth').':webilia-connect', true);
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
