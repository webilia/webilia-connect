<?php

namespace Webilia\Connect\Tests;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use Webilia\Connect\AuthorizationResult;
use Webilia\Connect\Client;
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
        return '1:'.hash('sha256', serialize([$integration, $capability]));
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

class InMemoryStorage implements Storage
{
    private ?array $connection;
    private array $pending = [];
    private array $authorizations = [];

    public function __construct(array $connection) { $this->connection = $connection; }
    public function connection(): ?array { return $this->connection; }
    public function saveConnection(array $connection): void { $this->connection = $connection; }
    public function forgetConnection(): void { $this->connection = null; }
    public function pending(string $state): ?array { return $this->pending[$state] ?? null; }
    public function savePending(array $pending): void { $this->pending[(string) $pending['state']] = $pending; }
    public function forgetPending(string $state): void { unset($this->pending[$state]); }
    public function authorization(string $key): ?array { return $this->authorizations[$key] ?? null; }
    public function saveAuthorization(string $key, array $authorization): void { $this->authorizations[$key] = $authorization; }
    public function forgetAuthorization(string $key): void { unset($this->authorizations[$key]); }
}

class ReadOnceStorage implements Storage
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
    public function forgetConnection(): void { $this->connection = null; }
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
