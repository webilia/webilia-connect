<?php

namespace Webilia\Connect\Contracts;

interface GetHttpClient extends HttpClient
{
    /**
     * @param array<string, scalar|null> $query
     * @param array<string, string> $headers
     * @return array<string, mixed>
     */
    public function get(string $url, array $query = [], array $headers = []): array;
}
