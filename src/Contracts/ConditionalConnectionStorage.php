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
     * Saves a connection only when the current credential and revision match the expected values.
     *
     * A null expected credential means that no connection may currently exist.
     *
     * @param array<string, mixed> $connection
     */
    public function saveConnectionIfCurrent(array $connection, ?string $expectedCredential, ?string $expectedRevision): bool;

    /** Removes a connection only when its credential and revision match. */
    public function forgetConnectionIfCurrent(string $expectedCredential, ?string $expectedRevision): bool;

    /** Removes a connection only when its credential matches, regardless of metadata revisions. */
    public function forgetConnectionWithCredential(string $expectedCredential): bool;
}
