<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Identity\UuidInterface;

interface AuthSessionManagerInterface
{
    /**
     * @param array<string, scalar|null> $metadata
     */
    public function create(
        UuidInterface $subjectId,
        AuthenticationEvidence $evidence,
        AuthSessionPolicy $policy,
        array $metadata = [],
    ): AuthSessionGrant;

    public function resume(
        #[\SensitiveParameter]
        SessionCredential $credential,
    ): ?AuthSession;

    /**
     * Updates activity only while the observed generation and activity time are
     * still current. Never revives an expired, revoked, or replaced session.
     */
    public function touch(AuthSession $observed): void;

    /**
     * Atomically replaces the bearer while preserving uuid and authenticatedAt.
     * Reauthentication requires a policy and records the supplied fresh proof
     * separately from cumulative evidence. A concurrent generation change fails
     * with ConcurrentSessionRotationException.
     */
    public function rotate(
        AuthSession $observed,
        AuthenticationEvidence $evidence,
        RotationReason $reason,
        ?AuthSessionPolicy $policy = null,
    ): AuthSessionGrant;

    public function revoke(
        UuidInterface $sessionId,
        RevocationReason $reason,
    ): void;

    public function revokePresentedCredential(
        #[\SensitiveParameter]
        SessionCredential $credential,
        RevocationReason $reason,
    ): void;

    public function revokeAll(
        UuidInterface $subjectId,
        ?UuidInterface $exceptSessionId = null,
        RevocationReason $reason = RevocationReason::UserRequested,
    ): void;

    /** Checks active state, generation, and credential before bearer publication. */
    public function isGrantCurrent(AuthSessionGrant $grant): bool;
}
