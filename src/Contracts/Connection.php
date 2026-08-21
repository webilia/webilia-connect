<?php

namespace Webilia\Connect\Contracts;

interface Connection
{
    public function active(): bool;

    public function credential(): string;

    public function siteUrl(): string;

    public function id(): ?int;

    /** @return array<string, mixed> */
    public function payload(): array;
}
