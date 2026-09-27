<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

use Componenta\Auth\AuthenticationAdmission;
use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\DeniedReasonInterface;
use Componenta\Identity\IdentityInterface;

final readonly class AuthenticatedSessionIssuer
{
    public function __construct(
        private AuthSessionManagerInterface $manager,
        private AuthSessionPolicyProviderInterface $policies,
        private AuthenticationAdmission $admission,
    ) {}

    /**
     * @param array<string, scalar|null> $metadata
     */
    public function issue(
        IdentityInterface $identity,
        AuthenticationEvidence $evidence,
        array $metadata = [],
    ): AuthSessionGrant|DeniedReasonInterface {
        $identity = $this->admission->check($identity->uuid, $evidence);

        if ($identity instanceof DeniedReasonInterface) {
            return $identity;
        }

        return $this->manager->create(
            $identity->uuid,
            $evidence,
            $this->policies->for($identity, $evidence),
            $metadata,
        );
    }

    /**
     * Reauthenticates an existing session through the same policy source used
     * for initial issuance.
     *
     * The manager receives only the fresh proof. Effective/cumulative evidence
     * remains a persistence concern, while policy selection may consider both
     * the existing evidence and the newly proven factor.
     */
    public function reauthenticate(
        AuthSession $session,
        IdentityInterface $identity,
        AuthenticationEvidence $proof,
    ): AuthSessionGrant|DeniedReasonInterface {
        if (!$session->subjectId->equals($identity->uuid)) {
            throw new \InvalidArgumentException(
                'Reauthentication identity must own the authentication session.',
            );
        }

        $identity = $this->admission->check($identity->uuid, $proof);

        if ($identity instanceof DeniedReasonInterface) {
            return $identity;
        }

        $effective = self::mergeEvidence($session->evidence, $proof);

        return $this->manager->rotate(
            $session,
            $proof,
            RotationReason::Reauthentication,
            $this->policies->for($identity, $effective),
        );
    }

    private static function mergeEvidence(
        AuthenticationEvidence $current,
        AuthenticationEvidence $proof,
    ): AuthenticationEvidence {
        return new AuthenticationEvidence(
            methods: array_values(array_unique([
                ...$current->methods,
                ...$proof->methods,
            ])),
            capabilities: array_values(array_unique([
                ...$current->capabilities,
                ...$proof->capabilities,
            ])),
        );
    }
}
