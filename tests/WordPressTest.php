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

    public function test_connection_remains_readable_after_authentication_salt_rotation(): void
    {
        $storage = new WordPressStorage();
        $connection = ['connection_id' => 1, 'credential' => 'wcx_test', 'site_url' => 'https://example.test', 'status' => 'active'];
        $storage->saveConnection($connection);
        WordPressTestState::$salt = 'rotated';

        $this->assertSame($connection, $storage->connection());
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

class WordPressMemoryStorage implements \Webilia\Connect\Contracts\Storage
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
    public function forgetConnection(): void { $this->connection = null; }
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
