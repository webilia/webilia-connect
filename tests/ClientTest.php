<?php

namespace Webilia\Connect\Tests;

use PHPUnit\Framework\TestCase;
use RuntimeException;
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
        $storage->saveAuthorization('1:vertex-addons-pro:vertex.pro.use', ['allowed' => true, 'cache_until' => time() + 60]);
        $client = new Client(new FailingHttpClient(), $storage);

        $result = $client->authorize('vertex-addons-pro', 'vertex.pro.use');

        $this->assertTrue($result->allowed());
        $this->assertTrue($result->payload()['cached']);
    }

    public function test_authorization_does_not_use_cached_allowance_for_a_permanent_failure(): void
    {
        $storage = new InMemoryStorage($this->connection());
        $storage->saveAuthorization('1:vertex-addons-pro:vertex.pro.use', ['allowed' => true, 'cache_until' => time() + 60]);
        $client = new Client(new PermanentFailingHttpClient(), $storage);

        $this->expectException(RequestException::class);
        $client->authorize('vertex-addons-pro', 'vertex.pro.use');
    }

    public function test_authorization_does_not_reuse_a_previous_connections_cache(): void
    {
        $storage = new InMemoryStorage($this->connection());
        $storage->saveAuthorization('1:vertex-addons-pro:vertex.pro.use', ['allowed' => true, 'cache_until' => time() + 60]);
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

        $cached = $storage->authorization('1:vertex-addons-pro:vertex.pro.use');
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
            $this->assertNotNull($storage->pending());
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

    private function connection(): array
    {
        return [
            'connection_id' => 1,
            'credential' => 'wcx_test',
            'site_url' => 'https://example.test',
            'status' => 'active',
        ];
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
    private ?array $pending = null;
    private array $authorizations = [];

    public function __construct(array $connection) { $this->connection = $connection; }
    public function connection(): ?array { return $this->connection; }
    public function saveConnection(array $connection): void { $this->connection = $connection; }
    public function forgetConnection(): void { $this->connection = null; }
    public function pending(): ?array { return $this->pending; }
    public function savePending(array $pending): void { $this->pending = $pending; }
    public function forgetPending(): void { $this->pending = null; }
    public function authorization(string $key): ?array { return $this->authorizations[$key] ?? null; }
    public function saveAuthorization(string $key, array $authorization): void { $this->authorizations[$key] = $authorization; }
    public function forgetAuthorization(string $key): void { unset($this->authorizations[$key]); }
}
