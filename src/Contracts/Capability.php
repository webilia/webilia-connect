<?php

namespace Webilia\Connect\Contracts;

interface Capability
{
    public function integration(): string;

    public function code(): string;
}
