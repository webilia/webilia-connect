<?php

namespace Webilia\Connect;

use Webilia\Connect\Contracts\Connection as ConnectionContract;

final class Connection implements ConnectionContract
{
    /** @var array<string, mixed> */
    private $payload;

    /** @param array<string, mixed> $payload */
    public function __construct(array $payload)
    {
        $this->payload = $payload;
    }

    public function active(): bool
    {
        return ($this->payload['status'] ?? null) === 'active' && $this->credential() !== '';
    }

    public function credential(): string
    {
        return (string) ($this->payload['credential'] ?? '');
    }

    public function siteUrl(): string
    {
        return (string) ($this->payload['site_url'] ?? '');
    }

    public function id(): ?int
    {
        return isset($this->payload['connection_id']) ? (int) $this->payload['connection_id'] : null;
    }

    /** @return array<string, mixed> */
    public function payload(): array
    {
        return $this->payload;
    }
}
