<?php

namespace Webilia\Connect;

use InvalidArgumentException;
use Webilia\Connect\Contracts\Capability as CapabilityContract;

final class Capability implements CapabilityContract
{
    private string $integration;
    private string $code;

    public function __construct(string $integration, string $code)
    {
        if ($integration === '' || $code === '') {
            throw new InvalidArgumentException('A capability requires an integration and code.');
        }

        $this->integration = $integration;
        $this->code = $code;
    }

    public function integration(): string
    {
        return $this->integration;
    }

    public function code(): string
    {
        return $this->code;
    }
}
