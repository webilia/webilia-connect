<?php

namespace Webilia\Connect\Contracts;

/**
 * Optional storage capability for atomically changing the shared connection record.
 *
 * Custom Storage adapters may implement this interface to preserve connection state
 * when concurrent WordPress requests complete, revoke, or disconnect a connection.
 */
interface ConditionalConnectionStorage
{
    /**
     * Saves a connection only when the current credential matches the expected value.
     *
     * A null expected credential means that no connection may currently exist.
     *
     * @param array<string, mixed> $connection
     */
    public function saveConnectionIfCurrent(array $connection, ?string $expectedCredential): bool;

    /** Removes a connection only when its credential matches. */
    public function forgetConnectionIfCurrent(string $expectedCredential): bool;
}
