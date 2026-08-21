<?php

namespace Webilia\Connect;

use RuntimeException;
use Webilia\Connect\Contracts\HttpClient;
use Webilia\Connect\Contracts\Storage;

final class Client
{
    private const CACHE_SECONDS = 864000;

    private HttpClient $http;
    private Storage $storage;
    private string $apiUrl;

    public function __construct(HttpClient $http, Storage $storage, string $apiUrl = 'https://api.webilia.com')
    {
        $this->http = $http;
        $this->storage = $storage;
        $this->apiUrl = rtrim($apiUrl, '/');
    }

    public function connection(): ?Connection
    {
        $payload = $this->storage->connection();

        return $payload ? new Connection($payload) : null;
    }

    public function isConnected(): bool
    {
        return (bool) ($this->connection() && $this->connection()->active());
    }

    /**
     * @return string Browser URL for the administrator to open.
     */
    public function begin(string $integration, string $siteUrl, string $returnUrl): string
    {
        $state = $this->randomToken();
        $verifier = $this->randomToken();
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

        $response = $this->http->post($this->endpoint('/v1/connect/authorization-requests'), [
            'integration' => $integration,
            'site_url' => $siteUrl,
            'return_url' => $returnUrl,
            'state' => $state,
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ]);

        $data = $this->data($response);
        $authorizationUrl = (string) ($data['authorization_url'] ?? '');
        $requestId = (string) ($data['request_id'] ?? '');

        if ($authorizationUrl === '' || $requestId === '') {
            throw new RuntimeException('Webilia Connect did not return an authorization URL.');
        }

        $this->storage->savePending([
            'request_id' => $requestId,
            'integration' => $integration,
            'site_url' => $siteUrl,
            'state' => $state,
            'verifier' => $verifier,
            'expires_at' => (int) ($data['expires_at'] ?? (time() + 600)),
        ]);

        return $authorizationUrl;
    }

    public function complete(string $code, string $state): Connection
    {
        $pending = $this->storage->pending();
        $this->storage->forgetPending();

        if (! $pending || (int) ($pending['expires_at'] ?? 0) < time()) {
            throw new RuntimeException('Your Webilia Connect request has expired. Please try again.');
        }

        if (! hash_equals((string) ($pending['state'] ?? ''), $state)) {
            throw new RuntimeException('Webilia Connect returned an invalid state.');
        }

        $response = $this->http->post($this->endpoint('/v1/connect/exchanges'), [
            'code' => $code,
            'code_verifier' => (string) $pending['verifier'],
        ]);

        $data = $this->data($response);
        $credential = (string) ($data['credential'] ?? '');
        if ($credential === '') {
            throw new RuntimeException('Webilia Connect did not return a site credential.');
        }

        $connection = [
            'connection_id' => (int) ($data['connection_id'] ?? 0),
            'credential' => $credential,
            'site_url' => (string) ($data['site_url'] ?? $pending['site_url']),
            'status' => (string) ($data['status'] ?? 'active'),
            'updated_at' => time(),
        ];

        $this->storage->saveConnection($connection);

        return new Connection($connection);
    }

    public function authorize(string $integration, string $capability): AuthorizationResult
    {
        $cacheKey = $integration.':'.$capability;
        $connection = $this->requiredConnection();

        try {
            $response = $this->http->post($this->endpoint('/v1/connect/authorizations'), [
                'integration' => $integration,
                'capability' => $capability,
            ], $this->bearer($connection));

            $data = $this->data($response);
            $result = new AuthorizationResult($data);

            if ($result->allowed()) {
                $payload = $result->payload();
                $payload['cache_until'] = time() + self::CACHE_SECONDS;
                $this->storage->saveAuthorization($cacheKey, $payload);
            } else {
                $this->storage->forgetAuthorization($cacheKey);
            }

            return $result;
        } catch (RuntimeException $exception) {
            $cached = $this->storage->authorization($cacheKey);
            if ($cached && (int) ($cached['cache_until'] ?? 0) >= time()) {
                $cached['cached'] = true;

                return new AuthorizationResult($cached);
            }

            throw $exception;
        }
    }

    /** @return array<string, mixed> */
    public function update(string $integration, string $basename, string $version, string $coreVersion = ''): array
    {
        $connection = $this->requiredConnection();

        return $this->data($this->http->post($this->endpoint('/v1/connect/integrations/'.$integration.'/updates'), [
            'basename' => $basename,
            'version' => $version,
            'core_version' => $coreVersion,
        ], $this->bearer($connection)));
    }

    public function disconnect(): void
    {
        $connection = $this->requiredConnection();
        $this->http->post($this->endpoint('/v1/connect/disconnect'), [], $this->bearer($connection));
        $this->storage->forgetConnection();
    }

    private function requiredConnection(): Connection
    {
        $connection = $this->connection();
        if (! $connection || ! $connection->active()) {
            throw new RuntimeException('This website is not connected to Webilia.');
        }

        return $connection;
    }

    /** @return array<string, string> */
    private function bearer(Connection $connection): array
    {
        return ['Authorization' => 'Bearer '.$connection->credential()];
    }

    /** @param array<string, mixed> $response @return array<string, mixed> */
    private function data(array $response): array
    {
        if (($response['success'] ?? true) === false) {
            throw new RuntimeException((string) ($response['message'] ?? 'Webilia Connect request failed.'));
        }

        $data = $response['data'] ?? $response;

        return is_array($data) ? $data : [];
    }

    private function endpoint(string $path): string
    {
        return $this->apiUrl.$path;
    }

    private function randomToken(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(48)), '+/', '-_'), '=');
    }
}
