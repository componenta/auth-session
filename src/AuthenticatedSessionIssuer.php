<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Identity\IdentityInterface;

final readonly class AuthenticatedSessionIssuer
{
    public function __construct(
        private AuthSessionManagerInterface $manager,
        private AuthSessionPolicyProviderInterface $policies,
    ) {}

    /**
     * @param array<string, scalar|null> $metadata
     */
    public function issue(
        IdentityInterface $identity,
        AuthenticationEvidence $evidence,
        array $metadata = [],
    ): AuthSessionGrant {
        return $this->manager->create(
            $identity->uuid,
            $evidence,
            $this->policies->for($identity, $evidence),
            $metadata,
        );
    }
}
