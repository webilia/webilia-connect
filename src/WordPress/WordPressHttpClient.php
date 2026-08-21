<?php

namespace Webilia\Connect\WordPress;

use RuntimeException;
use Webilia\Connect\Contracts\HttpClient;

final class WordPressHttpClient implements HttpClient
{
    /** @inheritDoc */
    public function post(string $url, array $payload, array $headers = []): array
    {
        $response = wp_remote_post($url, [
            'timeout' => 15,
            'headers' => array_merge(['Accept' => 'application/json', 'Content-Type' => 'application/json'], $headers),
            'body' => wp_json_encode($payload),
        ]);

        if (is_wp_error($response)) {
            throw new RuntimeException($response->get_error_message());
        }

        $body = json_decode((string) wp_remote_retrieve_body($response), true);
        if (! is_array($body)) {
            throw new RuntimeException('Webilia Connect returned an invalid response.');
        }

        if (wp_remote_retrieve_response_code($response) >= 400) {
            throw new RuntimeException((string) ($body['message'] ?? 'Webilia Connect request failed.'));
        }

        return $body;
    }
}
