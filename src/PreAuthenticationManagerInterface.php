<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

interface PreAuthenticationManagerInterface
{
    public function create(int $ttlSeconds = 300): PreAuthenticationGrant;

    /**
     * Atomically verifies and consumes a browser pre-authentication transaction.
     */
    public function consume(
        #[\SensitiveParameter]
        PreAuthenticationCredential $credential,
        #[\SensitiveParameter]
        PreAuthenticationRequestToken $requestToken,
    ): ?PreAuthenticationTransaction;
}
