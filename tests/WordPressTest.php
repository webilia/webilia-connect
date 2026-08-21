<?php

namespace Webilia\Connect\WordPress;

use PHPUnit\Framework\TestCase;
use Webilia\Connect\Client;
use Webilia\Connect\Contracts\HttpClient;

class WordPressStorageTest extends TestCase
{
    protected function setUp(): void
    {
        WordPressTestState::$options = [];
        WordPressTestState::$transients = [];
        WordPressTestState::$salt = 'initial';
    }

    public function test_authorization_cache_is_a_transient(): void
    {
        $storage = new WordPressStorage();
        $storage->saveAuthorization('key', ['allowed' => true, 'cache_until' => time() + 60]);

        $this->assertSame(['allowed' => true, 'cache_until' => WordPressTestState::$transients['webilia_connect_authorization_'.md5('key')]['value']['cache_until']], $storage->authorization('key'));
        $this->assertArrayNotHasKey('webilia_connect_authorization_'.md5('key'), WordPressTestState::$options);
    }

    public function test_expired_authorization_is_not_persisted(): void
    {
        $storage = new WordPressStorage();
        $storage->saveAuthorization('key', ['allowed' => true, 'cache_until' => time()]);

        $this->assertNull($storage->authorization('key'));
    }

    public function test_pending_request_is_stored_as_a_durable_option(): void
    {
        $storage = new WordPressStorage();
        $pending = ['state' => 'state', 'verifier' => 'verifier', 'expires_at' => time() + 60];
        $option = 'webilia_connect_pending_requests';
        $storage->savePending($pending);

        $this->assertSame($pending, $storage->pending('state'));
        $this->assertArrayHasKey($option, WordPressTestState::$options);
        $this->assertArrayNotHasKey($option, WordPressTestState::$transients);
        $this->assertArrayNotHasKey('webilia_connect_pending_requests_lock', WordPressTestState::$options);
    }

    public function test_saving_a_pending_request_cleans_expired_requests(): void
    {
        WordPressTestState::$options['webilia_connect_pending_requests'] = [
            'expired' => ['state' => 'expired', 'expires_at' => time() - 1],
        ];
        $storage = new WordPressStorage();
        $storage->savePending(['state' => 'active', 'verifier' => 'verifier', 'expires_at' => time() + 60]);

        $this->assertArrayNotHasKey('expired', WordPressTestState::$options['webilia_connect_pending_requests']);
        $this->assertSame('active', WordPressTestState::$options['webilia_connect_pending_requests']['active']['state']);
    }

    public function test_connection_remains_readable_after_authentication_salt_rotation(): void
    {
        $storage = new WordPressStorage();
        $connection = ['connection_id' => 1, 'credential' => 'wcx_test', 'site_url' => 'https://example.test', 'status' => 'active'];
        $storage->saveConnection($connection);
        WordPressTestState::$salt = 'rotated';

        $this->assertSame($connection, $storage->connection());
        $this->assertArrayNotHasKey('webilia_connect_encryption_key', WordPressTestState::$options);
    }

    public function test_conditional_connection_write_and_delete_require_the_current_credential(): void
    {
        $storage = new WordPressStorage();
        $connection = ['connection_id' => 1, 'credential' => 'wcx_test', 'site_url' => 'https://example.test', 'status' => 'active'];
        $replacement = ['connection_id' => 2, 'credential' => 'wcx_new', 'site_url' => 'https://example.test', 'status' => 'active'];
        $storage->saveConnection($connection);

        $this->assertFalse($storage->saveConnectionIfCurrent($replacement, 'wcx_other'));
        $this->assertTrue($storage->saveConnectionIfCurrent($replacement, 'wcx_test'));
        $this->assertFalse($storage->forgetConnectionIfCurrent('wcx_test'));
        $this->assertTrue($storage->forgetConnectionIfCurrent('wcx_new'));
        $this->assertNull($storage->connection());
        $this->assertArrayNotHasKey('webilia_connect_connection_lock', WordPressTestState::$options);
    }
}

class WordPressHttpClientTest extends TestCase
{
    public function test_empty_successful_response_returns_an_empty_payload(): void
    {
        WordPressTestState::$httpResponse = ['status' => 204, 'body' => ''];

        $payload = (new WordPressHttpClient())->post('https://api.webilia.test/v1/connect/disconnect', []);

        $this->assertSame([], $payload);
    }
}

class UpdateClientTest extends TestCase
{
    public function test_update_response_requires_a_boolean_allowance_and_package(): void
    {
        $connect = new Client(
            new WordPressSequenceHttpClient([
                ['data' => ['allowed' => true]],
                ['data' => ['allowed' => 'false', 'new_version' => '2.0.0', 'download_link' => 'https://example.test/update.zip']],
            ]),
            new WordPressMemoryStorage()
        );
        $client = new UpdateClient($connect, 'vertex-addons-pro', '1.0.0', 'vertex/vertex.php');
        $transient = (object) ['checked' => ['vertex/vertex.php' => '1.0.0']];

        $result = $client->checkUpdate($transient);

        $this->assertObjectNotHasProperty('response', $result);
    }

    public function test_update_response_requires_a_package_url(): void
    {
        $connect = new Client(
            new WordPressSequenceHttpClient([
                ['data' => ['allowed' => true]],
                ['data' => ['allowed' => true, 'new_version' => '2.0.0', 'download_link' => '']],
            ]),
            new WordPressMemoryStorage()
        );
        $client = new UpdateClient($connect, 'vertex-addons-pro', '1.0.0', 'vertex/vertex.php');
        $transient = (object) ['checked' => ['vertex/vertex.php' => '1.0.0']];

        $result = $client->checkUpdate($transient);

        $this->assertObjectNotHasProperty('response', $result);
    }
}

class WordPressSequenceHttpClient implements HttpClient
{
    /** @var array<int, array<string, mixed>> */
    private $responses;

    /** @param array<int, array<string, mixed>> $responses */
    public function __construct(array $responses)
    {
        $this->responses = $responses;
    }

    public function post(string $url, array $payload, array $headers = []): array
    {
        return array_shift($this->responses) ?? [];
    }
}

class WordPressMemoryStorage implements \Webilia\Connect\Contracts\Storage, \Webilia\Connect\Contracts\ConditionalConnectionStorage
{
    /** @var array<string, mixed>|null */
    private $connection = [
        'connection_id' => 1,
        'credential' => 'wcx_test',
        'site_url' => 'https://example.test',
        'status' => 'active',
    ];

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
    public function pending(string $state): ?array { return null; }
    public function savePending(array $pending): void {}
    public function forgetPending(string $state): void {}
    public function authorization(string $key): ?array { return null; }
    public function saveAuthorization(string $key, array $authorization): void {}
    public function forgetAuthorization(string $key): void {}
}

class WordPressTestState
{
    /** @var array<string, mixed> */
    public static $options = [];
    /** @var array<string, array{value:mixed, expires_at:int}> */
    public static $transients = [];
    public static $salt = 'initial';
    /** @var array{status:int, body:string} */
    public static $httpResponse = ['status' => 200, 'body' => '{}'];
}

function add_filter($hook, $callback, $priority = 10, $acceptedArgs = 1): void {}

function get_option($option, $default = false)
{
    return WordPressTestState::$options[$option] ?? $default;
}

function update_option($option, $value, $autoload = null): bool
{
    if (array_key_exists($option, WordPressTestState::$options) && WordPressTestState::$options[$option] === $value) {
        return false;
    }

    WordPressTestState::$options[$option] = $value;

    return true;
}

function delete_option($option): bool
{
    if (! array_key_exists($option, WordPressTestState::$options)) {
        return false;
    }

    unset(WordPressTestState::$options[$option]);

    return true;
}

function add_option($option, $value = '', $deprecated = '', $autoload = 'yes'): bool
{
    if (array_key_exists($option, WordPressTestState::$options)) {
        return false;
    }

    WordPressTestState::$options[$option] = $value;

    return true;
}

function get_transient($transient)
{
    $value = WordPressTestState::$transients[$transient] ?? null;
    if ($value === null || ($value['expires_at'] !== 0 && $value['expires_at'] <= time())) {
        unset(WordPressTestState::$transients[$transient]);

        return false;
    }

    return $value['value'];
}

function set_transient($transient, $value, $expiration = 0): bool
{
    WordPressTestState::$transients[$transient] = [
        'value' => $value,
        'expires_at' => $expiration > 0 ? time() + $expiration : 0,
    ];

    return true;
}

function delete_transient($transient): bool
{
    if (! array_key_exists($transient, WordPressTestState::$transients)) {
        return false;
    }

    unset(WordPressTestState::$transients[$transient]);

    return true;
}

function wp_json_encode($value): string
{
    return json_encode($value);
}

function wp_salt($scheme = 'auth'): string
{
    return WordPressTestState::$salt;
}

function wp_remote_post($url, array $args)
{
    return WordPressTestState::$httpResponse;
}

function is_wp_error($thing): bool
{
    return false;
}

function wp_remote_retrieve_response_code(array $response): int
{
    return $response['status'];
}

function wp_remote_retrieve_body(array $response): string
{
    return $response['body'];
}

if (! defined('WEBILIA_CONNECT_KEY')) {
    define('WEBILIA_CONNECT_KEY', 'webilia-connect-test-key');
}
