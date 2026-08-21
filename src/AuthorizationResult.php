<?php

namespace Webilia\Connect;

use Webilia\Connect\Contracts\AuthorizationResult as AuthorizationResultContract;

final class AuthorizationResult implements AuthorizationResultContract
{
    /** @var array<string, mixed> */
    private $payload;

    /** @param array<string, mixed> $payload */
    public function __construct(array $payload)
    {
        $this->payload = $payload;
    }

    public function allowed(): bool
    {
        return (bool) ($this->payload['allowed'] ?? false);
    }

    public function reason(): ?string
    {
        $reason = $this->payload['reason'] ?? null;

        return is_string($reason) && $reason !== '' ? $reason : null;
    }

    public function cacheUntil(): ?int
    {
        $value = $this->payload['cache_until'] ?? null;

        return is_numeric($value) ? (int) $value : null;
    }

    /** @return array<string, mixed> */
    public function payload(): array
    {
        return $this->payload;
    }
}
