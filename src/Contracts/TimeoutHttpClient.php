<?php

namespace Webilia\Connect\Contracts;

interface TimeoutHttpClient extends HttpClient
{
    /**
     * @param array<string, mixed> $payload
     * @param array<string, string> $headers
     * @return array<string, mixed>
     */
    public function postWithTimeout(string $url, array $payload, array $headers, int $timeout): array;
}
