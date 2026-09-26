<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

use Componenta\Identity\UuidInterface;

interface AuthSessionRegistryInterface
{
    public function find(UuidInterface $sessionId): ?AuthSession;

    /** @return list<AuthSession> */
    public function all(UuidInterface $subjectId): array;
}
