<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

final readonly class PreAuthenticationGrant
{
    public function __construct(
        public PreAuthenticationTransaction $transaction,
        #[\SensitiveParameter]
        public PreAuthenticationCredential $credential,
        #[\SensitiveParameter]
        public PreAuthenticationRequestToken $requestToken,
    ) {}

    /**
     * @return array{
     *     transactionId: string,
     *     credential: string,
     *     requestToken: string
     * }
     */
    public function __debugInfo(): array
    {
        return [
            'transactionId' => $this->transaction->uuid->toString(),
            'credential' => '[REDACTED]',
            'requestToken' => '[REDACTED]',
        ];
    }
}
