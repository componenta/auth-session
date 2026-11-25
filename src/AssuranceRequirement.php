<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

use DateTimeImmutable;

final readonly class AssuranceRequirement
{
    /** @var list<string> */
    public array $requiredMethods;

    /** @var list<string> */
    public array $requiredCapabilities;

    /**
     * @param list<string> $requiredMethods
     * @param list<string> $requiredCapabilities
     */
    public function __construct(
        array $requiredMethods = [],
        array $requiredCapabilities = [],
        public ?int $maxAge = null,
    ) {
        if ($this->maxAge !== null && $this->maxAge < 0) {
            throw new \InvalidArgumentException(
                'Assurance maximum age must be non-negative.',
            );
        }

        $this->requiredMethods = self::copyIdentifiers($requiredMethods);
        $this->requiredCapabilities = self::copyIdentifiers($requiredCapabilities);
    }

    public function isSatisfiedBy(
        AuthSession $session,
        DateTimeImmutable $now,
    ): bool {
        if (!$this->matches($session->evidence)) {
            return false;
        }

        if ($this->maxAge === null) {
            return true;
        }

        $cutoff = $now->modify(sprintf('-%d seconds', $this->maxAge));

        if (
            $session->authenticatedAt <= $now
            && $session->authenticatedAt >= $cutoff
            && (
                $session->reauthenticatedAt === null
                || $session->reauthenticatedAt <= $now
            )
        ) {
            return true;
        }

        if (
            $session->reauthenticatedAt !== null
            && $session->reauthenticatedAt <= $now
            && $session->reauthenticatedAt >= $cutoff
            && $session->reauthenticationEvidence !== null
        ) {
            return $this->matches($session->reauthenticationEvidence);
        }

        return false;
    }

    private function matches(
        \Componenta\Auth\AuthenticationEvidence $evidence,
    ): bool {
        foreach ($this->requiredMethods as $method) {
            if (!$evidence->hasMethod($method)) {
                return false;
            }
        }

        foreach ($this->requiredCapabilities as $capability) {
            if (!$evidence->hasCapability($capability)) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param list<string> $identifiers
     * @return list<string>
     */
    private static function copyIdentifiers(array $identifiers): array
    {
        $copy = [];

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

            // A readonly array must not retain caller-owned reference elements.
            $copy[] = $identifier;
        }

        return $copy;
    }
}
