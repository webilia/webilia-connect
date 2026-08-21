<?php

namespace Webilia\Connect\Tests;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use Webilia\Connect\Client;
use Webilia\Connect\Contracts\HttpClient;
use Webilia\Connect\Contracts\Storage;

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
        $storage->saveAuthorization('vertex-addons-pro:vertex.pro.use', ['allowed' => true, 'cache_until' => time() + 60]);
        $client = new Client(new FailingHttpClient(), $storage);

        $result = $client->authorize('vertex-addons-pro', 'vertex.pro.use');

        $this->assertTrue($result->allowed());
        $this->assertTrue($result->payload()['cached']);
    }
}

class FailingHttpClient implements HttpClient
{
    public function post(string $url, array $payload, array $headers = []): array
    {
        throw new RuntimeException('Network unavailable');
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
