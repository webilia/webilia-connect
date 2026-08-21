<?php

namespace Webilia\Connect\Contracts;

interface Storage
{
    /** @return array<string, mixed>|null */
    public function connection(): ?array;

    /** @param array<string, mixed> $connection */
    public function saveConnection(array $connection): void;

    public function forgetConnection(): void;

    /** @return array<string, mixed>|null */
    public function pending(string $state): ?array;

    /** @param array<string, mixed> $pending */
    public function savePending(array $pending): void;

    public function forgetPending(string $state): void;

    /** @return array<string, mixed>|null */
    public function authorization(string $key): ?array;

    /** @param array<string, mixed> $authorization */
    public function saveAuthorization(string $key, array $authorization): void;

    public function forgetAuthorization(string $key): void;
}
