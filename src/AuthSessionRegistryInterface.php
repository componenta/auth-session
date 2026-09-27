<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

use Componenta\Identity\UuidInterface;

/** Reads active sessions by public identity; never authenticates a bearer. */
interface AuthSessionRegistryInterface
{
    public function find(UuidInterface $sessionId): ?AuthSession;

    /** @return list<AuthSession> */
    public function all(UuidInterface $subjectId): array;
}
