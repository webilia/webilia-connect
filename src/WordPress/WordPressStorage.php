<?php

namespace Webilia\Connect\WordPress;

use RuntimeException;
use Webilia\Connect\Contracts\Storage;

final class WordPressStorage implements Storage
{
    private const CONNECTION_OPTION = 'webilia_connect_connection';
    private const PENDING_OPTION = 'webilia_connect_pending';
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
        update_option(self::CONNECTION_OPTION, $this->encrypt($connection), false);
    }

    public function forgetConnection(): void
    {
        delete_option(self::CONNECTION_OPTION);
    }

    public function pending(): ?array
    {
        $value = get_option(self::PENDING_OPTION, []);

        return is_array($value) ? $value : null;
    }

    public function savePending(array $pending): void
    {
        update_option(self::PENDING_OPTION, $pending, false);
    }

    public function forgetPending(): void
    {
        delete_option(self::PENDING_OPTION);
    }

    public function authorization(string $key): ?array
    {
        $value = get_option(self::AUTHORIZATION_PREFIX.md5($key), []);

        return is_array($value) ? $value : null;
    }

    public function saveAuthorization(string $key, array $authorization): void
    {
        update_option(self::AUTHORIZATION_PREFIX.md5($key), $authorization, false);
    }

    public function forgetAuthorization(string $key): void
    {
        delete_option(self::AUTHORIZATION_PREFIX.md5($key));
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
}
