<?php

namespace Webilia\Connect\Contracts;

interface UpdateClient
{
    /** @param mixed $transient @return mixed */
    public function checkUpdate($transient);

    /** @param mixed $false @param mixed $arg @return mixed */
    public function checkInfo($false, $action, $arg);
}
