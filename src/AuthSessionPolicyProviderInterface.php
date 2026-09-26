<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Identity\IdentityInterface;

interface AuthSessionPolicyProviderInterface
{
    public function for(
        IdentityInterface $identity,
        AuthenticationEvidence $evidence,
    ): AuthSessionPolicy;
}
