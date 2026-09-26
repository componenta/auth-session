<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

interface PreAuthenticationManagerInterface
{
    public function create(int $ttlSeconds = 300): PreAuthenticationGrant;

    /**
     * Verifies browser-bound pre-authentication secrets without consuming them.
     * Used before a fallible credential proof so invalid credentials do not
     * force the browser to restart the whole login flow.
     */
    public function verify(
        #[\SensitiveParameter]
        PreAuthenticationCredential $credential,
        #[\SensitiveParameter]
        PreAuthenticationRequestToken $requestToken,
    ): ?PreAuthenticationTransaction;

    /**
     * Atomically verifies and consumes a browser pre-authentication transaction.
     * Exactly one successful login completion may win.
     */
    public function consume(
        #[\SensitiveParameter]
        PreAuthenticationCredential $credential,
        #[\SensitiveParameter]
        PreAuthenticationRequestToken $requestToken,
    ): ?PreAuthenticationTransaction;
}
