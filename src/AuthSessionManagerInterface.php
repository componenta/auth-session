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

    public function touch(AuthSession $observed): void;

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
    ): void;

    public function isGrantCurrent(AuthSessionGrant $grant): bool;
}
