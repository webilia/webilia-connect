<?php

namespace Webilia\Connect\Contracts;

interface HttpClient
{
    /**
     * @param array<string, mixed> $payload
     * @param array<string, string> $headers
     * @return array<string, mixed>
     */
    public function post(string $url, array $payload, array $headers = []): array;
}
