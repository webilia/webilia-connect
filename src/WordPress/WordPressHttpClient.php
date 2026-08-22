<?php

namespace Webilia\Connect\WordPress;

use Webilia\Connect\Contracts\HttpClient;
use Webilia\Connect\Exception\RequestException;
use Webilia\Connect\Exception\TransientException;

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
            throw new TransientException($response->get_error_message());
        }

        $status = (int) wp_remote_retrieve_response_code($response);
        $rawBody = (string) wp_remote_retrieve_body($response);
        if ($status >= 200 && $status < 300 && trim($rawBody) === '') {
            return [];
        }

        $body = json_decode($rawBody, true);
        if (! is_array($body)) {
            if ($this->isTransientStatus($status)) {
                throw new TransientException('Webilia Connect returned an invalid response.');
            }

            throw new RequestException('Webilia Connect returned an invalid response.', $status);
        }

        if ($status < 200 || $status >= 300) {
            $message = (string) ($body['message'] ?? 'Webilia Connect request failed.');
            if ($this->isTransientStatus($status)) {
                throw new TransientException($message);
            }

            throw new RequestException($message, $status);
        }

        return $body;
    }

    private function isTransientStatus(int $status): bool
    {
        return $status === 408 || $status === 425 || $status === 429 || $status >= 500;
    }
}
