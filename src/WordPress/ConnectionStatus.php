<?php

namespace Webilia\Connect\WordPress;

use Webilia\Connect\Client;
use Webilia\Connect\Exception\RequestException;
use Webilia\Connect\Exception\TransientException;

/**
 * Cache on-demand connection checks across WordPress requests.
 */
final class ConnectionStatus
{
    private const SUCCESS_TRANSIENT = 'webilia_connect_status';
    private const BACKOFF_TRANSIENT = 'webilia_connect_status_backoff';
    private const SUCCESS_SECONDS = 300;

    private Client $client;
    private string $error = '';

    public function __construct(Client $client)
    {
        $this->client = $client;
    }

    public function isConnected(): bool
    {
        if (! $this->client->isConnected()) {
            self::clearCache();

            return false;
        }

        $connection = $this->client->connection();
        if (! $connection) {
            return false;
        }

        $credentialHash = hash('sha256', $connection->credential());
        if ($this->cached(self::SUCCESS_TRANSIENT, $credentialHash)
            || $this->cached(self::BACKOFF_TRANSIENT, $credentialHash)) {
            return true;
        }

        try {
            $connected = $this->client->verifyConnection();
            self::clearCache();
            if ($connected) {
                set_transient(self::SUCCESS_TRANSIENT, $credentialHash, self::SUCCESS_SECONDS);
            }

            return $connected;
        } catch (TransientException $exception) {
            $this->error = $exception->getMessage();
            // Keep the local connection during an outage and spread retries out.
            set_transient(self::BACKOFF_TRANSIENT, $credentialHash, wp_rand(30, 60));

            return true;
        } catch (RequestException $exception) {
            $this->error = $exception->getMessage();
            if ($exception->getCode() === 401) {
                self::clearCache();
            }

            return false;
        }
    }

    public function error(): string
    {
        return $this->error;
    }

    public static function clearCache(): void
    {
        delete_transient(self::SUCCESS_TRANSIENT);
        delete_transient(self::BACKOFF_TRANSIENT);
    }

    private function cached(string $name, string $credentialHash): bool
    {
        return get_transient($name) === $credentialHash;
    }
}
