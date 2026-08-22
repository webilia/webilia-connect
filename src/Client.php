<?php

namespace Webilia\Connect;

use RuntimeException;
use Webilia\Connect\Contracts\ConditionalConnectionStorage;
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
        if ($previousConnection) {
            $this->retryPendingRevocation($previousConnection);
            $previousConnection = $this->connection();
            if ($previousConnection && $this->hasPendingRevocations($previousConnection)) {
                throw new RuntimeException('Unable to replace the existing Webilia connection until its previous credential is revoked.');
            }
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
            'connection_revision' => $this->randomToken(),
            'updated_at' => time(),
        ];

        $completedConnection = new Connection($connection);
        if (! $this->belongsToCurrentSite($completedConnection)) {
            $this->revokeCredential($credential);
            $this->forgetCompletedPending($state);

            throw new RuntimeException('Webilia Connect returned a connection for a different website.');
        }

        if ($previousConnection && $previousConnection->active() && $this->belongsToCurrentSite($previousConnection) && $previousConnection->credential() !== $credential) {
            $connection['pending_revocation_credential'] = $previousConnection->credential();
        }

        $completedConnection = new Connection($connection);

        try {
            if (! $this->saveConnectionIfCurrent($connection, $previousConnection)) {
                throw new RuntimeException('The Webilia Connect connection changed while this request was completing.');
            }
        } catch (\Throwable $exception) {
            if (! $this->revokeCredential($credential)) {
                $this->queuePendingRevocation($credential);
            }
            $this->forgetCompletedPending($state);

            throw $exception;
        }

        $this->forgetCompletedPending($state);
        $this->retryPendingRevocation($completedConnection);

        return $completedConnection;
    }

    public function authorize(string $integration, string $capability): AuthorizationResult
    {
        $connection = $this->requiredConnection();
        $this->retryPendingRevocation($connection);
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
                $this->cacheAuthorization($cacheKey, $result, $connection);
            } elseif ($cacheKey !== null) {
                $this->invalidateCachedAuthorization($cacheKey, $connection);
            }

            return $result;
        } catch (RequestException $exception) {
            if ($exception->getCode() === 401) {
                $this->forgetRejectedConnection($connection);
            }
            if ($cacheKey !== null) {
                $this->invalidateCachedAuthorization($cacheKey, $connection);
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
        $this->retryPendingRevocation($connection);
        $connection = $this->requiredConnection();

        try {
            return $this->data($this->http->post($this->endpoint('/v1/connect/integrations/'.rawurlencode($integration).'/updates'), [
                'basename' => $basename,
                'version' => $version,
                'core_version' => $coreVersion,
            ], $this->bearer($connection)));
        } catch (RequestException $exception) {
            if ($exception->getCode() === 401) {
                $this->forgetRejectedConnection($connection);
            }

            throw $exception;
        }
    }

    public function disconnect(): void
    {
        $connection = $this->connection();
        if (! $connection) {
            throw new RuntimeException('This website is not connected to Webilia.');
        }

        if (! $this->belongsToCurrentSite($connection)) {
            $this->forgetConnectionIfCurrent($connection);

            return;
        }

        if (! $connection->active()) {
            $this->retryPendingRevocation($connection);
            $currentConnection = $this->connection();
            if ($currentConnection
                && hash_equals($connection->credential(), $currentConnection->credential())
                && ! $this->hasPendingRevocations($currentConnection)) {
                $this->forgetConnectionIfCurrent($currentConnection);

                return;
            }

            if ($currentConnection
                && hash_equals($connection->credential(), $currentConnection->credential())
                && $this->hasPendingRevocations($currentConnection)) {
                throw new RuntimeException('Unable to disconnect until the previous Webilia credential is revoked.');
            }

            return;
        }

        $this->retryPendingRevocation($connection);
        $currentConnection = $this->connection();
        if (! $currentConnection
            || ! hash_equals($connection->credential(), $currentConnection->credential())
            || $this->hasPendingRevocations($currentConnection)) {
            throw new RuntimeException('Unable to disconnect until the previous Webilia credential is revoked.');
        }

        $connection = $currentConnection;

        try {
            $this->data($this->http->post($this->endpoint('/v1/connect/disconnect'), [], $this->bearer($connection)));
        } catch (RequestException $exception) {
            if ($exception->getCode() !== 401) {
                throw $exception;
            }
        }

        $this->forgetConnectionWithCredential($connection->credential());
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
            if ($exception instanceof RequestException && $exception->getCode() === 401) {
                return true;
            }

            // Callers decide whether a failed best-effort cleanup may be ignored.

            return false;
        }
    }

    private function forgetRejectedConnection(Connection $rejected): void
    {
        try {
            $current = $rejected;
            for ($attempt = 0; $attempt < 2; ++$attempt) {
                $payload = $current->payload();
                if ($this->pendingRevocationCredentials($payload) !== []) {
                    $payload['status'] = 'revoked';
                    $payload['connection_revision'] = $this->randomToken();
                    if ($this->saveConnectionIfCurrent($payload, $current)) {
                        return;
                    }
                } elseif ($this->forgetConnectionIfCurrent($current)) {
                    return;
                }

                $current = $this->connection();
                if (! $current || ! hash_equals($current->credential(), $rejected->credential())) {
                    return;
                }
            }
        } catch (\Throwable $exception) {
            // Preserve the authorization error when local cleanup cannot be completed.
        }
    }

    private function retryPendingRevocation(Connection $connection): void
    {
        $payload = $connection->payload();
        $credentials = $this->pendingRevocationCredentials($payload);
        if ($credentials === []) {
            return;
        }

        $remaining = [];
        foreach ($credentials as $credential) {
            if (! $this->revokeCredential($credential)) {
                $remaining[] = $credential;
            }
        }

        if ($remaining === $credentials) {
            return;
        }

        $this->setPendingRevocationCredentials($payload, $remaining);
        $payload['connection_revision'] = $this->randomToken();
        try {
            $this->saveConnectionIfCurrent($payload, $connection);
        } catch (\Throwable $exception) {
            // Retain the encrypted cleanup record for a later retry.
        }
    }

    private function invalidateCachedAuthorization(string $cacheKey, Connection $connection): void
    {
        try {
            $this->storage->forgetAuthorization($cacheKey);

            return;
        } catch (\Throwable $exception) {
            $current = $connection;
            $generation = (string) ($connection->payload()['authorization_cache_generation'] ?? '');
            for ($attempt = 0; $attempt < 2; ++$attempt) {
                $payload = $current->payload();
                if ((string) ($payload['authorization_cache_generation'] ?? '') !== $generation) {
                    return;
                }

                $payload['authorization_cache_generation'] = $this->randomToken();
                $payload['connection_revision'] = $this->randomToken();
                try {
                    if ($this->saveConnectionIfCurrent($payload, $current)) {
                        return;
                    }
                } catch (\Throwable $exception) {
                    break;
                }

                $current = $this->connection();
                if (! $current || ! hash_equals($current->credential(), $connection->credential())) {
                    return;
                }
            }

            try {
                $this->forgetConnectionIfCurrent($current);
            } catch (\Throwable $exception) {
                // A broken local storage backend cannot guarantee cache invalidation.
            }
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

    /** @param array<string, mixed> $connection */
    private function saveConnectionIfCurrent(array $connection, ?Connection $expectedConnection): bool
    {
        $expectedCredential = $expectedConnection ? $expectedConnection->credential() : null;
        $expectedRevision = $this->connectionRevision($expectedConnection);
        if ($this->storage instanceof ConditionalConnectionStorage) {
            return $this->storage->saveConnectionIfCurrent($connection, $expectedCredential, $expectedRevision);
        }

        $current = $this->connection();
        if (($current ? $current->credential() : null) !== $expectedCredential || $this->connectionRevision($current) !== $expectedRevision) {
            return false;
        }

        $this->storage->saveConnection($connection);

        return true;
    }

    private function forgetConnectionIfCurrent(Connection $expectedConnection): bool
    {
        $expectedCredential = $expectedConnection->credential();
        $expectedRevision = $this->connectionRevision($expectedConnection);
        if ($this->storage instanceof ConditionalConnectionStorage) {
            return $this->storage->forgetConnectionIfCurrent($expectedCredential, $expectedRevision);
        }

        $current = $this->connection();
        if (! $current || ! hash_equals($current->credential(), $expectedCredential) || $this->connectionRevision($current) !== $expectedRevision) {
            return false;
        }

        $this->storage->forgetConnection();

        return true;
    }

    private function forgetConnectionWithCredential(string $expectedCredential): bool
    {
        if ($this->storage instanceof ConditionalConnectionStorage) {
            return $this->storage->forgetConnectionWithCredential($expectedCredential);
        }

        $current = $this->connection();
        if (! $current || ! hash_equals($current->credential(), $expectedCredential)) {
            return false;
        }

        $this->storage->forgetConnection();

        return true;
    }

    private function connectionRevision(?Connection $connection): ?string
    {
        if (! $connection || ! isset($connection->payload()['connection_revision'])) {
            return null;
        }

        return (string) $connection->payload()['connection_revision'];
    }

    private function hasPendingRevocations(Connection $connection): bool
    {
        return $this->pendingRevocationCredentials($connection->payload()) !== [];
    }

    /** @param array<string, mixed> $payload @return string[] */
    private function pendingRevocationCredentials(array $payload): array
    {
        $credentials = [];
        $legacyCredential = (string) ($payload['pending_revocation_credential'] ?? '');
        if ($legacyCredential !== '') {
            $credentials[] = $legacyCredential;
        }

        $queued = $payload['pending_revocation_credentials'] ?? [];
        if (is_array($queued)) {
            foreach ($queued as $credential) {
                if (is_string($credential) && $credential !== '') {
                    $credentials[] = $credential;
                }
            }
        }

        return array_values(array_unique($credentials));
    }

    /** @param array<string, mixed> $payload @param string[] $credentials */
    private function setPendingRevocationCredentials(array &$payload, array $credentials): void
    {
        unset($payload['pending_revocation_credential'], $payload['pending_revocation_credentials']);
        if (count($credentials) === 1) {
            $payload['pending_revocation_credential'] = $credentials[0];

            return;
        }

        if ($credentials !== []) {
            $payload['pending_revocation_credentials'] = array_values(array_unique($credentials));
        }
    }

    private function queuePendingRevocation(string $credential): void
    {
        for ($attempt = 0; $attempt < 2; ++$attempt) {
            $connection = $this->connection();
            if (! $connection) {
                $payload = [
                    'connection_id' => 0,
                    'credential' => '',
                    'site_url' => $this->siteUrl,
                    'status' => 'revoked',
                    'connection_revision' => $this->randomToken(),
                ];
                $this->setPendingRevocationCredentials($payload, [$credential]);

                try {
                    $this->saveConnectionIfCurrent($payload, null);
                } catch (\Throwable $exception) {
                    // No durable storage is available to retain the cleanup tombstone.
                }

                return;
            }

            if (! $this->belongsToCurrentSite($connection)) {
                return;
            }

            $payload = $connection->payload();
            $credentials = $this->pendingRevocationCredentials($payload);
            if (in_array($credential, $credentials, true)) {
                return;
            }

            $credentials[] = $credential;
            $this->setPendingRevocationCredentials($payload, $credentials);
            $payload['connection_revision'] = $this->randomToken();
            try {
                if ($this->saveConnectionIfCurrent($payload, $connection)) {
                    return;
                }
            } catch (\Throwable $exception) {
                return;
            }
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
            ? $connectionId.':'.hash('sha256', serialize([$connection->credential(), (string) ($connection->payload()['authorization_cache_generation'] ?? ''), $integration, $capability]))
            : null;
    }

    private function cacheAuthorization(?string $cacheKey, AuthorizationResult $result, Connection $connection): void
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
            try {
                $this->storage->forgetAuthorization($cacheKey);
            } catch (\Throwable $exception) {
                // Expired cache entries are never accepted during an outage.
            }

            return;
        }

        $payload['cache_until'] = $cacheUntil;
        try {
            $this->storage->saveAuthorization($cacheKey, $payload);
        } catch (\Throwable $exception) {
            // The fresh API authorization is valid, but an older outage cache is not.
            $this->invalidateCachedAuthorization($cacheKey, $connection);
        }
    }
}
