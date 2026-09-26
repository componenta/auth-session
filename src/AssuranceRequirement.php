<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

use DateTimeImmutable;

final readonly class AssuranceRequirement
{
    /**
     * @param list<string> $requiredMethods
     * @param list<string> $requiredCapabilities
     */
    public function __construct(
        public array $requiredMethods = [],
        public array $requiredCapabilities = [],
        public ?int $maxAge = null,
    ) {
        if ($this->maxAge !== null && $this->maxAge < 0) {
            throw new \InvalidArgumentException(
                'Assurance maximum age must be non-negative.',
            );
        }

        self::assertIdentifiers($this->requiredMethods);
        self::assertIdentifiers($this->requiredCapabilities);
    }

    public function isSatisfiedBy(
        AuthSession $session,
        DateTimeImmutable $now,
    ): bool {
        foreach ($this->requiredMethods as $method) {
            if (!$session->evidence->hasMethod($method)) {
                return false;
            }
        }

        foreach ($this->requiredCapabilities as $capability) {
            if (!$session->evidence->hasCapability($capability)) {
                return false;
            }
        }

        if ($this->maxAge === null) {
            return true;
        }

        $establishedAt = $session->reauthenticatedAt ?? $session->authenticatedAt;

        return $establishedAt <= $now
            && $establishedAt >= $now->modify(sprintf('-%d seconds', $this->maxAge));
    }

    /** @param list<string> $identifiers */
    private static function assertIdentifiers(array $identifiers): void
    {
        foreach ($identifiers as $identifier) {
            if (
                $identifier === ''
                || strlen($identifier) > 128
                || preg_match('/\A[a-z0-9][a-z0-9._:-]*\z/D', $identifier) !== 1
            ) {
                throw new \InvalidArgumentException(
                    'Assurance identifier is invalid.',
                );
            }
        }
    }
}
