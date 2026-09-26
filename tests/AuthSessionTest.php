<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Tests;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\Session\AssuranceRequirement;
use Componenta\Auth\Session\AuthSession;
use Componenta\Identity\Uuid;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class AuthSessionTest extends TestCase
{
    public function testAssuranceChecksEvidenceAndFreshness(): void
    {
        $session = self::session(
            new AuthenticationEvidence(
                ['webauthn'],
                ['user_verified', 'phishing_resistant'],
            ),
            reauthenticatedAt: new DateTimeImmutable('2030-01-01T00:09:00+00:00'),
            reauthenticationEvidence: new AuthenticationEvidence(
                ['webauthn'],
                ['user_verified', 'phishing_resistant'],
            ),
        );
        $requirement = new AssuranceRequirement(
            requiredCapabilities: ['phishing_resistant', 'user_verified'],
            maxAge: 120,
        );

        self::assertTrue($requirement->isSatisfiedBy(
            $session,
            new DateTimeImmutable('2030-01-01T00:10:00+00:00'),
        ));
        self::assertFalse($requirement->isSatisfiedBy(
            $session,
            new DateTimeImmutable('2030-01-01T00:12:01+00:00'),
        ));
    }

    public function testFreshWeakReauthenticationDoesNotRefreshStaleStrongEvidence(): void
    {
        $session = self::session(
            new AuthenticationEvidence(
                ['webauthn', 'recovery_code'],
                ['phishing_resistant', 'recovery'],
            ),
            reauthenticatedAt: new DateTimeImmutable(
                '2030-01-01T00:09:00+00:00',
            ),
            reauthenticationEvidence: new AuthenticationEvidence(
                ['recovery_code'],
                ['recovery'],
            ),
        );

        self::assertFalse((new AssuranceRequirement(
            requiredCapabilities: ['phishing_resistant'],
            maxAge: 120,
        ))->isSatisfiedBy(
            $session,
            new DateTimeImmutable('2030-01-01T00:10:00+00:00'),
        ));

        self::assertTrue((new AssuranceRequirement(
            requiredCapabilities: ['recovery'],
            maxAge: 120,
        ))->isSatisfiedBy(
            $session,
            new DateTimeImmutable('2030-01-01T00:10:00+00:00'),
        ));
    }

    public function testRejectsSecretMetadataKeys(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        self::session(
            new AuthenticationEvidence(['session']),
            metadata: ['csrf_token' => 'secret'],
        );
    }

    /** @param array<string, scalar|null> $metadata */
    private static function session(
        AuthenticationEvidence $evidence,
        ?DateTimeImmutable $reauthenticatedAt = null,
        array $metadata = [],
        ?AuthenticationEvidence $reauthenticationEvidence = null,
    ): AuthSession {
        $created = new DateTimeImmutable('2030-01-01T00:00:00+00:00');
        $lastActive = new DateTimeImmutable('2030-01-01T00:09:00+00:00');

        return new AuthSession(
            uuid: Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc'),
            subjectId: Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abd'),
            evidence: $evidence,
            credentialGeneration: 1,
            createdAt: $created,
            authenticatedAt: $created,
            reauthenticatedAt: $reauthenticatedAt,
            lastActiveAt: $lastActive,
            idleExpiresAt: new DateTimeImmutable('2030-01-01T00:30:00+00:00'),
            absoluteExpiresAt: new DateTimeImmutable('2030-01-02T00:00:00+00:00'),
            metadata: $metadata,
            reauthenticationEvidence: $reauthenticationEvidence,
        );
    }
}
