<?php

namespace Webilia\Connect\Tests;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use Webilia\Connect\AuthorizationResult;
use Webilia\Connect\Client;
use Webilia\Connect\Contracts\ConditionalConnectionStorage;
use Webilia\Connect\Contracts\HttpClient;
use Webilia\Connect\Contracts\Storage;
use Webilia\Connect\Exception\RequestException;
use Webilia\Connect\Exception\TransientException;

class ClientTest extends TestCase
{
    public function test_authorization_uses_a_cached_allowance_during_an_outage(): void
    {
        $storage = new InMemoryStorage([
            'connection_id' => 1,
            'credential' => 'wcx_test',
            'site_url' => 'https://example.test',
            'status' => 'active',
        ]);
        $storage->saveAuthorization($this->authorizationKey('vertex-addons-pro', 'vertex.pro.use'), ['allowed' => true, 'cache_until' => time() + 60]);
        $client = new Client(new FailingHttpClient(), $storage);

        $result = $client->authorize('vertex-addons-pro', 'vertex.pro.use');

        $this->assertTrue($result->allowed());
        $this->assertTrue($result->payload()['cached']);
    }

    public function test_authorization_does_not_use_cached_allowance_for_a_permanent_failure(): void
    {
        $storage = new InMemoryStorage($this->connection());
        $storage->saveAuthorization($this->authorizationKey('vertex-addons-pro', 'vertex.pro.use'), ['allowed' => true, 'cache_until' => time() + 60]);
        $client = new Client(new PermanentFailingHttpClient(), $storage);

        try {
            $client->authorize('vertex-addons-pro', 'vertex.pro.use');
            $this->fail('Expected a permanent authorization failure.');
        } catch (RequestException $exception) {
            $this->assertNull($storage->authorization($this->authorizationKey('vertex-addons-pro', 'vertex.pro.use')));
        }
    }

    public function test_a_401_authorization_failure_removes_the_rejected_connection(): void
    {
        $storage = new InMemoryStorage($this->connection());
        $client = new Client(new RevokedHttpClient(), $storage);

        $this->expectException(RequestException::class);
        try {
            $client->authorize('vertex-addons-pro', 'vertex.pro.use');
        } finally {
            $this->assertNull($storage->connection());
        }
    }

    public function test_a_401_authorization_failure_removes_the_connection_when_cache_cleanup_fails(): void
    {
        $storage = new FailingAuthorizationCleanupStorage($this->connection());
        $client = new Client(new RevokedHttpClient(), $storage);

        $this->expectException(RequestException::class);
        try {
            $client->authorize('vertex-addons-pro', 'vertex.pro.use');
        } finally {
            $this->assertNull($storage->connection());
        }
    }

    public function test_a_fresh_authorization_succeeds_when_cache_writing_fails(): void
    {
        $storage = new FailingAuthorizationWriteStorage($this->connection());
        $client = new Client(new SuccessfulHttpClient(['data' => ['allowed' => true]]), $storage);

        $this->assertTrue($client->authorize('vertex-addons-pro', 'vertex.pro.use')->allowed());
    }

    public function test_authorization_evicts_a_cached_allowance_for_an_application_failure(): void
    {
        $storage = new InMemoryStorage($this->connection());
        $key = $this->authorizationKey('vertex-addons-pro', 'vertex.pro.use');
        $storage->saveAuthorization($key, ['allowed' => true, 'cache_until' => time() + 60]);
        $client = new Client(new SuccessfulHttpClient(['success' => false, 'message' => 'Connection revoked']), $storage);

        try {
            $client->authorize('vertex-addons-pro', 'vertex.pro.use');
            $this->fail('Expected an application-level authorization failure.');
        } catch (RequestException $exception) {
            $this->assertNull($storage->authorization($key));
        }
    }

    public function test_denial_cannot_reuse_a_cached_allowance_when_cache_cleanup_fails(): void
    {
        $storage = new FailingAuthorizationCleanupStorage($this->connection());
        $storage->saveAuthorization($this->authorizationKey('vertex-addons-pro', 'vertex.pro.use'), ['allowed' => true, 'cache_until' => time() + 60]);
        $client = new Client(new SuccessfulHttpClient(['data' => ['allowed' => false]]), $storage);

        $this->assertFalse($client->authorize('vertex-addons-pro', 'vertex.pro.use')->allowed());
        $this->assertNotEmpty($storage->connection()['authorization_cache_generation']);

        $this->expectException(TransientException::class);
        (new Client(new FailingHttpClient(), $storage))->authorize('vertex-addons-pro', 'vertex.pro.use');
    }

    public function test_authorization_requires_a_boolean_allowance(): void
    {
        $this->assertFalse((new AuthorizationResult(['allowed' => 'false']))->allowed());
        $this->assertTrue((new AuthorizationResult(['allowed' => true]))->allowed());
    }

    public function test_authorization_does_not_reuse_a_previous_connections_cache(): void
    {
        $storage = new InMemoryStorage($this->connection());
        $storage->saveAuthorization($this->authorizationKey('vertex-addons-pro', 'vertex.pro.use'), ['allowed' => true, 'cache_until' => time() + 60]);
        $newConnection = $this->connection();
        $newConnection['connection_id'] = 2;
        $storage->saveConnection($newConnection);
        $client = new Client(new FailingHttpClient(), $storage);

        $this->expectException(TransientException::class);
        $client->authorize('vertex-addons-pro', 'vertex.pro.use');
    }

    public function test_authorization_caps_cache_at_the_server_expiry(): void
    {
        $storage = new InMemoryStorage($this->connection());
        $client = new Client(new SuccessfulHttpClient(['data' => ['allowed' => true, 'cache_until' => time() + 30]]), $storage);

        $client->authorize('vertex-addons-pro', 'vertex.pro.use');

        $cached = $storage->authorization($this->authorizationKey('vertex-addons-pro', 'vertex.pro.use'));
        $this->assertNotNull($cached);
        $this->assertLessThanOrEqual(time() + 30, $cached['cache_until']);
    }

    public function test_invalid_callback_state_keeps_the_pending_request(): void
    {
        $storage = new InMemoryStorage($this->connection());
        $storage->savePending(['state' => 'expected', 'verifier' => 'verifier', 'expires_at' => time() + 60]);
        $client = new Client(new SuccessfulHttpClient([]), $storage);

        try {
            $client->complete('code', 'wrong');
            $this->fail('Expected an invalid state exception.');
        } catch (RuntimeException $exception) {
            $this->assertNotNull($storage->pending('expected'));
        }
    }

    public function test_failed_disconnect_keeps_the_connection(): void
    {
        $storage = new InMemoryStorage($this->connection());
        $client = new Client(new SuccessfulHttpClient(['success' => false, 'message' => 'Unable to disconnect']), $storage);

        $this->expectException(RuntimeException::class);
        try {
            $client->disconnect();
        } finally {
            $this->assertNotNull($storage->connection());
        }
    }

    public function test_malformed_disconnect_success_flag_keeps_the_connection(): void
    {
        $storage = new InMemoryStorage($this->connection());
        $client = new Client(new SuccessfulHttpClient(['success' => 'false']), $storage);

        $this->expectException(RequestException::class);
        try {
            $client->disconnect();
        } finally {
            $this->assertNotNull($storage->connection());
        }
    }

    public function test_is_connected_reads_the_connection_once(): void
    {
        $storage = new ReadOnceStorage($this->connection());
        $client = new Client(new SuccessfulHttpClient([]), $storage);

        $this->assertTrue($client->isConnected());
        $this->assertSame(1, $storage->connectionReads());
    }

    public function test_a_connection_copied_to_a_different_site_is_rejected(): void
    {
        $client = new Client(
            new SuccessfulHttpClient([]),
            new InMemoryStorage($this->connection()),
            'https://api.webilia.test',
            'https://clone.test'
        );

        $this->assertFalse($client->isConnected());
        $this->expectException(RuntimeException::class);
        $client->authorize('vertex-addons-pro', 'vertex.pro.use');
    }

    public function test_a_mismatched_pending_request_is_not_exchanged(): void
    {
        $storage = new InMemoryStorage($this->connection());
        $storage->savePending([
            'state' => 'state',
            'verifier' => 'verifier',
            'site_url' => 'https://example.test',
            'expires_at' => time() + 60,
        ]);
        $http = new CountingHttpClient();
        $client = new Client($http, $storage, 'https://api.webilia.test', 'https://clone.test');

        try {
            $client->complete('code', 'state');
            $this->fail('Expected the mismatched request to be rejected.');
        } catch (RuntimeException $exception) {
            $this->assertSame(0, $http->calls());
            $this->assertNull($storage->pending('state'));
        }
    }

    public function test_a_mismatched_connection_can_be_disconnected(): void
    {
        $storage = new InMemoryStorage($this->connection());
        $http = new CountingHttpClient();
        $client = new Client($http, $storage, 'https://api.webilia.test', 'https://clone.test');

        $client->disconnect();

        $this->assertNull($storage->connection());
        $this->assertSame(0, $http->calls());
    }

    public function test_mismatched_exchange_credential_is_revoked(): void
    {
        $storage = new InMemoryStorage($this->connection());
        $storage->savePending([
            'state' => 'state',
            'verifier' => 'verifier',
            'site_url' => 'https://example.test',
            'expires_at' => time() + 60,
        ]);
        $http = new SequenceHttpClient([
            ['data' => ['connection_id' => 2, 'credential' => 'wcx_mismatch', 'site_url' => 'https://wrong.test', 'status' => 'active']],
            [],
        ]);
        $client = new Client($http, $storage, 'https://api.webilia.test', 'https://example.test');

        $this->expectException(RuntimeException::class);
        try {
            $client->complete('code', 'state');
        } finally {
            $this->assertSame(2, $http->calls());
            $this->assertSame(['Authorization' => 'Bearer wcx_mismatch'], $http->headers(1));
            $this->assertNull($storage->pending('state'));
        }
    }

    public function test_exchange_credential_is_revoked_when_persistence_fails(): void
    {
        $storage = new FailingConnectionStorage($this->connection());
        $storage->savePending([
            'state' => 'state',
            'verifier' => 'verifier',
            'site_url' => 'https://example.test',
            'expires_at' => time() + 60,
        ]);
        $http = new SequenceHttpClient([
            ['data' => ['connection_id' => 2, 'credential' => 'wcx_new', 'site_url' => 'https://example.test', 'status' => 'active']],
            [],
        ]);
        $client = new Client($http, $storage, 'https://api.webilia.test', 'https://example.test');

        $this->expectException(RuntimeException::class);
        try {
            $client->complete('code', 'state');
        } finally {
            $this->assertSame(2, $http->calls());
            $this->assertSame(['Authorization' => 'Bearer wcx_new'], $http->headers(1));
            $this->assertNull($storage->pending('state'));
        }
    }

    public function test_exchange_does_not_replace_a_connection_saved_concurrently(): void
    {
        $storage = new ConcurrentExchangeStorage($this->connection());
        $storage->savePending([
            'state' => 'state',
            'verifier' => 'verifier',
            'site_url' => 'https://example.test',
            'expires_at' => time() + 60,
        ]);
        $http = new SequenceHttpClient([
            ['data' => ['connection_id' => 2, 'credential' => 'wcx_new', 'site_url' => 'https://example.test', 'status' => 'active']],
            [],
        ]);

        $this->expectException(RuntimeException::class);
        try {
            (new Client($http, $storage, 'https://api.webilia.test', 'https://example.test'))->complete('code', 'state');
        } finally {
            $this->assertSame('wcx_concurrent', $storage->connection()['credential']);
            $this->assertSame(['Authorization' => 'Bearer wcx_new'], $http->headers(1));
        }
    }

    public function test_pending_revocation_does_not_overwrite_a_newer_connection(): void
    {
        $connection = $this->connection();
        $connection['pending_revocation_credential'] = 'wcx_old';
        $storage = new ConcurrentRevocationStorage($connection);
        $http = new SequenceHttpClient([
            [],
            ['data' => ['allowed' => true]],
        ]);

        $this->assertTrue((new Client($http, $storage, 'https://api.webilia.test', 'https://example.test'))->authorize('vertex-addons-pro', 'vertex.pro.use')->allowed());
        $this->assertSame('wcx_concurrent', $storage->connection()['credential']);
    }

    public function test_disconnect_does_not_remove_a_connection_saved_concurrently(): void
    {
        $storage = new InMemoryStorage($this->connection());
        $client = new Client(new ReplacingDisconnectHttpClient($storage), $storage, 'https://api.webilia.test', 'https://example.test');

        $client->disconnect();

        $this->assertSame('wcx_concurrent', $storage->connection()['credential']);
    }

    public function test_replaced_connection_credential_is_revoked(): void
    {
        $storage = new InMemoryStorage($this->connection());
        $storage->savePending([
            'state' => 'state',
            'verifier' => 'verifier',
            'site_url' => 'https://example.test',
            'expires_at' => time() + 60,
        ]);
        $http = new SequenceHttpClient([
            ['data' => ['connection_id' => 2, 'credential' => 'wcx_new', 'site_url' => 'https://example.test', 'status' => 'active']],
            [],
        ]);
        $client = new Client($http, $storage, 'https://api.webilia.test', 'https://example.test');

        $client->complete('code', 'state');

        $this->assertSame(2, $http->calls());
        $this->assertSame(['Authorization' => 'Bearer wcx_test'], $http->headers(1));
        $this->assertSame('wcx_new', $storage->connection()['credential']);
    }

    public function test_failed_replacement_keeps_the_previous_connection(): void
    {
        $storage = new InMemoryStorage($this->connection());
        $storage->savePending([
            'state' => 'state',
            'verifier' => 'verifier',
            'site_url' => 'https://example.test',
            'expires_at' => time() + 60,
        ]);
        $http = new SequenceHttpClient([
            ['data' => ['connection_id' => 2, 'credential' => 'wcx_new', 'site_url' => 'https://example.test', 'status' => 'active']],
            new TransientException('Unable to revoke the previous credential.'),
            [],
        ]);
        $client = new Client($http, $storage, 'https://api.webilia.test', 'https://example.test');

        $client->complete('code', 'state');

        $this->assertSame(2, $http->calls());
        $this->assertSame(['Authorization' => 'Bearer wcx_test'], $http->headers(1));
        $this->assertSame('wcx_new', $storage->connection()['credential']);
        $this->assertSame('wcx_test', $storage->connection()['pending_revocation_credential']);
    }

    public function test_default_site_ports_match_the_same_site(): void
    {
        $client = new Client(
            new SuccessfulHttpClient([]),
            new InMemoryStorage($this->connection()),
            'https://api.webilia.test',
            'https://example.test:443'
        );

        $this->assertTrue($client->isConnected());
    }

    public function test_inactive_connections_can_be_disconnected_locally(): void
    {
        $connection = $this->connection();
        $connection['status'] = 'revoked';
        $storage = new InMemoryStorage($connection);
        $http = new CountingHttpClient();
        $client = new Client($http, $storage);

        $client->disconnect();

        $this->assertNull($storage->connection());
        $this->assertSame(0, $http->calls());
    }

    public function test_authorization_cache_keys_do_not_collide(): void
    {
        $storage = new InMemoryStorage($this->connection());
        $online = new Client(new SuccessfulHttpClient(['data' => ['allowed' => true, 'cache_for_seconds' => 60]]), $storage);
        $online->authorize('a:b', 'c');
        $offline = new Client(new FailingHttpClient(), $storage);

        $this->expectException(TransientException::class);
        $offline->authorize('a', 'b:c');
    }

    public function test_pending_requests_are_preserved_by_state(): void
    {
        $storage = new InMemoryStorage($this->connection());
        $first = ['state' => 'first', 'verifier' => 'first-verifier', 'expires_at' => time() + 60];
        $second = ['state' => 'second', 'verifier' => 'second-verifier', 'expires_at' => time() + 60];

        $storage->savePending($first);
        $storage->savePending($second);

        $this->assertSame($first, $storage->pending('first'));
        $this->assertSame($second, $storage->pending('second'));
    }

    public function test_pending_cleanup_failure_does_not_mask_a_completed_connection(): void
    {
        $storage = new FailingPendingCleanupStorage($this->connection());
        $storage->savePending(['state' => 'state', 'verifier' => 'verifier', 'site_url' => 'https://example.test', 'expires_at' => time() + 60]);
        $client = new Client(new SuccessfulHttpClient(['data' => [
            'connection_id' => 1,
            'credential' => 'wcx_new',
            'site_url' => 'https://example.test',
            'status' => 'active',
        ]]), $storage);

        $connection = $client->complete('code', 'state');

        $this->assertSame('wcx_new', $connection->credential());
    }

    public function test_disconnect_cleans_up_an_already_revoked_credential(): void
    {
        $storage = new InMemoryStorage($this->connection());
        $client = new Client(new RevokedHttpClient(), $storage);

        $client->disconnect();

        $this->assertNull($storage->connection());
    }

    public function test_update_encodes_the_integration_path_segment(): void
    {
        $http = new RecordingHttpClient(['data' => ['allowed' => true]]);
        $client = new Client($http, new InMemoryStorage($this->connection()));

        $client->update('foo/bar', 'plugin/plugin.php', '1.0.0');

        $this->assertStringContainsString('/integrations/foo%2Fbar/updates', $http->url());
    }

    private function connection(): array
    {
        return [
            'connection_id' => 1,
            'credential' => 'wcx_test',
            'site_url' => 'https://example.test',
            'status' => 'active',
        ];
    }

    private function authorizationKey(string $integration, string $capability): string
    {
        return '1:'.hash('sha256', serialize(['wcx_test', '', $integration, $capability]));
    }
}

class FailingHttpClient implements HttpClient
{
    public function post(string $url, array $payload, array $headers = []): array
    {
        throw new TransientException('Network unavailable');
    }
}

class PermanentFailingHttpClient implements HttpClient
{
    public function post(string $url, array $payload, array $headers = []): array
    {
        throw new RequestException('Connection revoked');
    }
}

class RevokedHttpClient implements HttpClient
{
    public function post(string $url, array $payload, array $headers = []): array
    {
        throw new RequestException('Connection revoked', 401);
    }
}

class RecordingHttpClient implements HttpClient
{
    private array $response;
    private string $lastUrl = '';

    public function __construct(array $response)
    {
        $this->response = $response;
    }

    public function post(string $url, array $payload, array $headers = []): array
    {
        $this->lastUrl = $url;

        return $this->response;
    }

    public function url(): string
    {
        return $this->lastUrl;
    }
}

class SuccessfulHttpClient implements HttpClient
{
    private array $response;

    public function __construct(array $response)
    {
        $this->response = $response;
    }

    public function post(string $url, array $payload, array $headers = []): array
    {
        return $this->response;
    }
}

class CountingHttpClient implements HttpClient
{
    private int $calls = 0;

    public function post(string $url, array $payload, array $headers = []): array
    {
        ++$this->calls;

        return [];
    }

    public function calls(): int
    {
        return $this->calls;
    }
}

class SequenceHttpClient implements HttpClient
{
    private array $responses;
    private array $headers = [];

    public function __construct(array $responses)
    {
        $this->responses = $responses;
    }

    public function post(string $url, array $payload, array $headers = []): array
    {
        $this->headers[] = $headers;

        $response = array_shift($this->responses) ?? [];
        if ($response instanceof \Throwable) {
            throw $response;
        }

        return $response;
    }

    public function calls(): int
    {
        return count($this->headers);
    }

    public function headers(int $index): array
    {
        return $this->headers[$index] ?? [];
    }
}

class InMemoryStorage implements Storage, ConditionalConnectionStorage
{
    private ?array $connection;
    private array $pending = [];
    private array $authorizations = [];

    public function __construct(array $connection) { $this->connection = $connection; }
    public function connection(): ?array { return $this->connection; }
    public function saveConnection(array $connection): void { $this->connection = $connection; }
    public function saveConnectionIfCurrent(array $connection, ?string $expectedCredential): bool
    {
        if (($this->connection['credential'] ?? null) !== $expectedCredential) { return false; }
        $this->connection = $connection;

        return true;
    }
    public function forgetConnection(): void { $this->connection = null; }
    public function forgetConnectionIfCurrent(string $expectedCredential): bool
    {
        if (($this->connection['credential'] ?? null) !== $expectedCredential) { return false; }
        $this->connection = null;

        return true;
    }
    public function pending(string $state): ?array { return $this->pending[$state] ?? null; }
    public function savePending(array $pending): void { $this->pending[(string) $pending['state']] = $pending; }
    public function forgetPending(string $state): void { unset($this->pending[$state]); }
    public function authorization(string $key): ?array { return $this->authorizations[$key] ?? null; }
    public function saveAuthorization(string $key, array $authorization): void { $this->authorizations[$key] = $authorization; }
    public function forgetAuthorization(string $key): void { unset($this->authorizations[$key]); }
}

class ReadOnceStorage implements Storage, ConditionalConnectionStorage
{
    private ?array $connection;
    private int $reads = 0;

    public function __construct(array $connection)
    {
        $this->connection = $connection;
    }

    public function connection(): ?array
    {
        ++$this->reads;

        return $this->reads === 1 ? $this->connection : null;
    }

    public function connectionReads(): int { return $this->reads; }
    public function saveConnection(array $connection): void { $this->connection = $connection; }
    public function saveConnectionIfCurrent(array $connection, ?string $expectedCredential): bool
    {
        if (($this->connection['credential'] ?? null) !== $expectedCredential) { return false; }
        $this->connection = $connection;

        return true;
    }
    public function forgetConnection(): void { $this->connection = null; }
    public function forgetConnectionIfCurrent(string $expectedCredential): bool
    {
        if (($this->connection['credential'] ?? null) !== $expectedCredential) { return false; }
        $this->connection = null;

        return true;
    }
    public function pending(string $state): ?array { return null; }
    public function savePending(array $pending): void {}
    public function forgetPending(string $state): void {}
    public function authorization(string $key): ?array { return null; }
    public function saveAuthorization(string $key, array $authorization): void {}
    public function forgetAuthorization(string $key): void {}
}

class FailingPendingCleanupStorage extends InMemoryStorage
{
    public function forgetPending(string $state): void
    {
        throw new RuntimeException('Pending cleanup failed.');
    }
}

class FailingConnectionStorage extends InMemoryStorage
{
    public function saveConnection(array $connection): void
    {
        throw new RuntimeException('Unable to persist the connection.');
    }

    public function saveConnectionIfCurrent(array $connection, ?string $expectedCredential): bool
    {
        throw new RuntimeException('Unable to persist the connection.');
    }
}

class FailingAuthorizationCleanupStorage extends InMemoryStorage
{
    public function forgetAuthorization(string $key): void
    {
        throw new RuntimeException('Unable to clear the authorization cache.');
    }
}

class FailingAuthorizationWriteStorage extends InMemoryStorage
{
    public function saveAuthorization(string $key, array $authorization): void
    {
        throw new RuntimeException('Unable to write the authorization cache.');
    }
}

class ConcurrentExchangeStorage extends InMemoryStorage
{
    public function saveConnectionIfCurrent(array $connection, ?string $expectedCredential): bool
    {
        $this->saveConnection([
            'connection_id' => 3,
            'credential' => 'wcx_concurrent',
            'site_url' => 'https://example.test',
            'status' => 'active',
        ]);

        return false;
    }
}

class ConcurrentRevocationStorage extends InMemoryStorage
{
    public function saveConnectionIfCurrent(array $connection, ?string $expectedCredential): bool
    {
        $this->saveConnection([
            'connection_id' => 3,
            'credential' => 'wcx_concurrent',
            'site_url' => 'https://example.test',
            'status' => 'active',
        ]);

        return false;
    }
}

class ReplacingDisconnectHttpClient implements HttpClient
{
    private InMemoryStorage $storage;

    public function __construct(InMemoryStorage $storage)
    {
        $this->storage = $storage;
    }

    public function post(string $url, array $payload, array $headers = []): array
    {
        $this->storage->saveConnection([
            'connection_id' => 3,
            'credential' => 'wcx_concurrent',
            'site_url' => 'https://example.test',
            'status' => 'active',
        ]);

        return [];
    }
}
