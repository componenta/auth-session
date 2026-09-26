<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

use Componenta\Identity\UuidInterface;
use DateTimeImmutable;

final readonly class PreAuthenticationTransaction
{
    public function __construct(
        public UuidInterface $uuid,
        public DateTimeImmutable $createdAt,
        public DateTimeImmutable $expiresAt,
    ) {
        if ($this->expiresAt <= $this->createdAt) {
            throw new \InvalidArgumentException(
                'Pre-authentication transaction must expire after creation.',
            );
        }
    }
}
