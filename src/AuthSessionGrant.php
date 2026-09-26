<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

final readonly class AuthSessionGrant
{
    public function __construct(
        public AuthSession $session,
        #[\SensitiveParameter]
        public SessionCredential $credential,
    ) {}

    /** @return array{sessionId: string, credential: string} */
    public function __debugInfo(): array
    {
        return [
            'sessionId' => $this->session->uuid->toString(),
            'credential' => '[REDACTED]',
        ];
    }
}
