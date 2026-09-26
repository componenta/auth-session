<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

final readonly class AuthSessionPolicy
{
    private const int MAX_TIMEOUT = 315_360_000;

    public function __construct(
        public int $idleTimeout,
        public int $absoluteTimeout,
        public ?int $maximumConcurrentSessions = null,
        public ConcurrentSessionOverflow $overflow = ConcurrentSessionOverflow::RejectNew,
    ) {
        foreach ([
            'idleTimeout' => $this->idleTimeout,
            'absoluteTimeout' => $this->absoluteTimeout,
        ] as $name => $value) {
            if ($value < 1 || $value > self::MAX_TIMEOUT) {
                throw new \InvalidArgumentException(sprintf(
                    '%s must be between 1 and %d seconds.',
                    $name,
                    self::MAX_TIMEOUT,
                ));
            }
        }

        if ($this->absoluteTimeout < $this->idleTimeout) {
            throw new \InvalidArgumentException(
                'Absolute timeout must be greater than or equal to idle timeout.',
            );
        }

        if (
            $this->maximumConcurrentSessions !== null
            && $this->maximumConcurrentSessions < 1
        ) {
            throw new \InvalidArgumentException(
                'Maximum concurrent sessions must be greater than zero.',
            );
        }
    }
}
