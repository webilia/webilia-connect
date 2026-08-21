<?php

namespace Webilia\Connect;

use RuntimeException;
use Webilia\Connect\Contracts\HttpClient;
use Webilia\Connect\Contracts\Storage;
use Webilia\Connect\Exception\RequestException;
use Webilia\Connect\Exception\TransientException;

final class Client
{
    private const CACHE_SECONDS = 864000;

    private HttpClient $http;
    private Storage $storage;
    private string $apiUrl;
    private string $siteUrl;

    public function __construct(HttpClient $http, Storage $storage, string $apiUrl = 'https://api.webilia.com', string $siteUrl = '')
    {
        $this->http = $http;
        $this->storage = $storage;
        $this->apiUrl = rtrim($apiUrl, '/');
        $this->siteUrl = $this->normalizeSiteUrl($siteUrl !== '' ? $siteUrl : $this->wordpressSiteUrl());
    }

    public function connection(): ?Connection
    {
        $payload = $this->storage->connection();

        return $payload ? new Connection($payload) : null;
    }

    public function isConnected(): bool
    {
        $connection = $this->connection();

        return $connection !== null && $connection->active() && $this->belongsToCurrentSite($connection);
    }

    /**
     * @return string Browser URL for the administrator to open.
     */
    public function begin(string $integration, string $siteUrl, string $returnUrl): string
    {
        if (! $this->siteMatchesCurrentSite($siteUrl)) {
            throw new RuntimeException('Webilia Connect can only connect the current website.');
        }

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
        $pending = $this->storage->pending($state);

        if (! $pending || (int) ($pending['expires_at'] ?? 0) < time()) {
            if ($pending) {
                $this->storage->forgetPending($state);
            }

            throw new RuntimeException('Your Webilia Connect request has expired. Please try again.');
        }

        if (! hash_equals((string) ($pending['state'] ?? ''), $state)) {
            throw new RuntimeException('Webilia Connect returned an invalid state.');
        }

        if (! $this->siteMatchesCurrentSite((string) ($pending['site_url'] ?? ''))) {
            $this->storage->forgetPending($state);

            throw new RuntimeException('This Webilia Connect request belongs to a different website.');
        }

        $previousConnection = $this->connection();
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

        $completedConnection = new Connection($connection);
        if (! $this->belongsToCurrentSite($completedConnection)) {
            $this->revokeCredential($credential);
            $this->forgetCompletedPending($state);

            throw new RuntimeException('Webilia Connect returned a connection for a different website.');
        }

        if ($previousConnection && $previousConnection->active() && $this->belongsToCurrentSite($previousConnection) && $previousConnection->credential() !== $credential) {
            if (! $this->revokeCredential($previousConnection->credential())) {
                $this->revokeCredential($credential);
                $this->forgetCompletedPending($state);

                throw new RuntimeException('Unable to replace the existing Webilia connection. Please try again.');
            }
        }

        try {
            $this->storage->saveConnection($connection);
        } catch (\Throwable $exception) {
            $this->revokeCredential($credential);
            $this->forgetCompletedPending($state);

            throw $exception;
        }

        $this->forgetCompletedPending($state);

        return $completedConnection;
    }

    public function authorize(string $integration, string $capability): AuthorizationResult
    {
        $connection = $this->requiredConnection();
        $cacheKey = $this->cacheKey($integration, $capability, $connection);

        try {
            $response = $this->http->post($this->endpoint('/v1/connect/authorizations'), [
                'integration' => $integration,
                'capability' => $capability,
            ], $this->bearer($connection));

            $data = $this->data($response);
            $result = new AuthorizationResult($data);

            if ($result->allowed()) {
                $this->cacheAuthorization($cacheKey, $result);
            } elseif ($cacheKey !== null) {
                $this->storage->forgetAuthorization($cacheKey);
            }

            return $result;
        } catch (RequestException $exception) {
            if ($cacheKey !== null) {
                $this->storage->forgetAuthorization($cacheKey);
            }
            if ($exception->getCode() === 401) {
                $this->forgetRejectedConnection($connection);
            }

            throw $exception;
        } catch (TransientException $exception) {
            $cached = $cacheKey === null ? null : $this->storage->authorization($cacheKey);
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

        return $this->data($this->http->post($this->endpoint('/v1/connect/integrations/'.rawurlencode($integration).'/updates'), [
            'basename' => $basename,
            'version' => $version,
            'core_version' => $coreVersion,
        ], $this->bearer($connection)));
    }

    public function disconnect(): void
    {
        $connection = $this->connection();
        if (! $connection) {
            throw new RuntimeException('This website is not connected to Webilia.');
        }

        if (! $connection->active() || ! $this->belongsToCurrentSite($connection)) {
            $this->storage->forgetConnection();

            return;
        }

        try {
            $this->data($this->http->post($this->endpoint('/v1/connect/disconnect'), [], $this->bearer($connection)));
        } catch (RequestException $exception) {
            if ($exception->getCode() !== 401) {
                throw $exception;
            }
        }

        $this->storage->forgetConnection();
    }

    private function requiredConnection(): Connection
    {
        $connection = $this->activeConnection();
        if (! $this->belongsToCurrentSite($connection)) {
            throw new RuntimeException('This website is not connected to Webilia.');
        }

        return $connection;
    }

    private function activeConnection(): Connection
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
        if (array_key_exists('success', $response) && $response['success'] !== true) {
            throw new RequestException((string) ($response['message'] ?? 'Webilia Connect request failed.'));
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

    private function revokeCredential(string $credential): bool
    {
        try {
            $this->data($this->http->post($this->endpoint('/v1/connect/disconnect'), [], [
                'Authorization' => 'Bearer '.$credential,
            ]));

            return true;
        } catch (\Throwable $exception) {
            // Callers decide whether a failed best-effort cleanup may be ignored.

            return false;
        }
    }

    private function forgetRejectedConnection(Connection $rejected): void
    {
        try {
            $current = $this->connection();
            if ($current && hash_equals($current->credential(), $rejected->credential())) {
                $this->storage->forgetConnection();
            }
        } catch (\Throwable $exception) {
            // Preserve the authorization error when local cleanup cannot be completed.
        }
    }

    private function forgetCompletedPending(string $state): void
    {
        try {
            $this->storage->forgetPending($state);
        } catch (\Throwable $exception) {
            // The connection is already durable; its expiring pending record is safe to leave behind.
        }
    }

    private function belongsToCurrentSite(Connection $connection): bool
    {
        return $this->siteMatchesCurrentSite($connection->siteUrl());
    }

    private function siteMatchesCurrentSite(string $siteUrl): bool
    {
        return $this->siteUrl === '' || $this->siteUrl === $this->normalizeSiteUrl($siteUrl);
    }

    private function wordpressSiteUrl(): string
    {
        return function_exists('get_site_url') ? (string) get_site_url() : '';
    }

    private function normalizeSiteUrl(string $siteUrl): string
    {
        $parts = parse_url($siteUrl);
        if (! is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
            return rtrim($siteUrl, '/');
        }

        $scheme = strtolower((string) $parts['scheme']);
        $normalized = $scheme.'://'.strtolower((string) $parts['host']);
        $port = isset($parts['port']) ? (int) $parts['port'] : null;
        if ($port !== null && ! (($scheme === 'http' && $port === 80) || ($scheme === 'https' && $port === 443))) {
            $normalized .= ':'.$parts['port'];
        }

        return $normalized.rtrim((string) ($parts['path'] ?? ''), '/');
    }

    private function cacheKey(string $integration, string $capability, Connection $connection): ?string
    {
        $connectionId = $connection->id();

        return $connectionId !== null && $connectionId > 0
            ? $connectionId.':'.hash('sha256', serialize([$integration, $capability]))
            : null;
    }

    private function cacheAuthorization(?string $cacheKey, AuthorizationResult $result): void
    {
        if ($cacheKey === null) {
            return;
        }

        $now = time();
        $payload = $result->payload();
        $cacheUntil = $result->cacheUntil();
        if ($cacheUntil === null && is_numeric($payload['cache_for_seconds'] ?? null)) {
            $cacheUntil = $now + max(0, (int) $payload['cache_for_seconds']);
        }

        $cacheUntil = min($cacheUntil ?? ($now + self::CACHE_SECONDS), $now + self::CACHE_SECONDS);
        if ($cacheUntil <= $now) {
            $this->storage->forgetAuthorization($cacheKey);

            return;
        }

        $payload['cache_until'] = $cacheUntil;
        $this->storage->saveAuthorization($cacheKey, $payload);
    }
}
