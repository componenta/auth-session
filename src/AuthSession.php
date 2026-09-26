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

    /** @var array<string, scalar|null> */
    public array $metadata;

    /**
     * @param array<string, mixed> $metadata
     */
    public function __construct(
        public UuidInterface $uuid,
        public UuidInterface $subjectId,
        public AuthenticationEvidence $evidence,
        public int $credentialGeneration,
        public DateTimeImmutable $createdAt,
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
            $this->authenticatedAt < $this->createdAt
            || $this->lastActiveAt < $this->authenticatedAt
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

        self::assertMetadata($metadata);

        /** @var array<string, scalar|null> $metadata */
        $this->metadata = $metadata;
    }

    /** @param array<string, mixed> $metadata */
    private static function assertMetadata(array $metadata): void
    {
        if (count($metadata) > self::MAX_METADATA_ENTRIES) {
            throw new \InvalidArgumentException('Too many session metadata entries.');
        }

        foreach ($metadata as $key => $value) {
            if (
                $key === ''
                || strlen($key) > self::MAX_METADATA_KEY_LENGTH
                || preg_match('/\A[a-zA-Z0-9][a-zA-Z0-9._-]*\z/D', $key) !== 1
            ) {
                throw new \InvalidArgumentException('Session metadata key is invalid.');
            }

            if (
                preg_match('/(?:credential|token|secret|password|otp|csrf)/i', $key) === 1
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
        }
    }
}
