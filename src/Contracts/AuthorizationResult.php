<?php

namespace Webilia\Connect\Contracts;

interface AuthorizationResult
{
    public function allowed(): bool;

    public function reason(): ?string;

    public function cacheUntil(): ?int;

    /** @return array<string, mixed> */
    public function payload(): array;
}
