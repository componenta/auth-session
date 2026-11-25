<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\AuthenticationStateInterface;
use Componenta\Identity\UuidInterface;
use DateTimeImmutable;

final readonly class AuthSession implements AuthenticationStateInterface
{
    private const int MAX_METADATA_ENTRIES = 32;
    private const int MAX_METADATA_KEY_LENGTH = 64;
    private const int MAX_METADATA_STRING_LENGTH = 1024;

    /** @var array<array-key, scalar|null> */
    public array $metadata;

    /**
     * @param array<array-key, mixed> $metadata
     */
    public function __construct(
        public UuidInterface $uuid,
        public UuidInterface $subjectId,
        public AuthenticationEvidence $evidence,
        public int $credentialGeneration,
        public DateTimeImmutable $authenticatedAt,
        public ?DateTimeImmutable $reauthenticatedAt,
        public DateTimeImmutable $lastActiveAt,
        public DateTimeImmutable $idleExpiresAt,
        public DateTimeImmutable $absoluteExpiresAt,
        array $metadata = [],
        public ?AuthenticationEvidence $reauthenticationEvidence = null,
    ) {
        if ($this->credentialGeneration < 1) {
            throw new \InvalidArgumentException(
                'Credential generation must be greater than zero.',
            );
        }

        if (
            $this->lastActiveAt < $this->authenticatedAt
            || $this->idleExpiresAt <= $this->lastActiveAt
            || $this->absoluteExpiresAt <= $this->authenticatedAt
            || $this->idleExpiresAt > $this->absoluteExpiresAt
        ) {
            throw new \InvalidArgumentException(
                'Authentication-session timestamps are inconsistent.',
            );
        }

        if (
            $this->reauthenticatedAt !== null
            && (
                $this->reauthenticatedAt < $this->authenticatedAt
                || $this->reauthenticatedAt > $this->lastActiveAt
            )
        ) {
            throw new \InvalidArgumentException(
                'Reauthentication timestamp is inconsistent.',
            );
        }

        if (
            ($this->reauthenticatedAt === null)
            !== ($this->reauthenticationEvidence === null)
        ) {
            throw new \InvalidArgumentException(
                'Reauthentication timestamp and evidence must be present together.',
            );
        }

        $this->metadata = self::copyMetadata($metadata);
    }

    /**
     * @param array<array-key, mixed> $metadata
     * @return array<array-key, scalar|null>
     */
    private static function copyMetadata(array $metadata): array
    {
        if (count($metadata) > self::MAX_METADATA_ENTRIES) {
            throw new \InvalidArgumentException('Too many session metadata entries.');
        }

        $copy = [];

        foreach ($metadata as $key => $value) {
            $name = (string) $key;

            if (
                $name === ''
                || strlen($name) > self::MAX_METADATA_KEY_LENGTH
                || preg_match('/\A[a-zA-Z0-9][a-zA-Z0-9._-]*\z/D', $name) !== 1
            ) {
                throw new \InvalidArgumentException('Session metadata key is invalid.');
            }

            if (
                preg_match('/(?:credential|token|secret|password|otp|csrf)/i', $name) === 1
            ) {
                throw new \InvalidArgumentException(
                    'Session metadata cannot contain secret-bearing fields.',
                );
            }

            if (!is_scalar($value) && $value !== null) {
                throw new \InvalidArgumentException(
                    'Session metadata values must be scalar or null.',
                );
            }

            if (
                is_string($value)
                && (
                    strlen($value) > self::MAX_METADATA_STRING_LENGTH
                    || preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', $value) === 1
                )
            ) {
                throw new \InvalidArgumentException('Session metadata value is invalid.');
            }

            // Copy scalar values so caller references cannot change validated state.
            $copy[$key] = $value;
        }

        return $copy;
    }
}
