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

    public function testFreshHistoricalProofCannotRestoreRemovedCurrentAssurance(): void
    {
        $proof = new AuthenticationEvidence(['webauthn'], ['phishing_resistant']);
        $reauthenticatedAt = new DateTimeImmutable('2030-01-01T00:09:00+00:00');
        // Privilege-change rotation may replace current evidence while keeping
        // the earlier reauthentication timestamp and proof for history.
        $changed = self::session(
            new AuthenticationEvidence(['password'], ['knowledge']),
            reauthenticatedAt: $reauthenticatedAt,
            reauthenticationEvidence: $proof,
        );
        $retained = self::session(
            new AuthenticationEvidence(['password', 'webauthn'], ['knowledge', 'phishing_resistant']),
            reauthenticatedAt: $reauthenticatedAt,
            reauthenticationEvidence: $proof,
        );
        $now = new DateTimeImmutable('2030-01-01T00:10:00+00:00');

        foreach ([
            new AssuranceRequirement(requiredMethods: ['webauthn'], maxAge: 120),
            new AssuranceRequirement(requiredCapabilities: ['phishing_resistant'], maxAge: 120),
        ] as $requirement) {
            self::assertFalse($requirement->isSatisfiedBy($changed, $now));
            self::assertTrue($requirement->isSatisfiedBy($retained, $now));
        }
    }

    public function testRejectsSecretMetadataKeys(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        self::session(
            new AuthenticationEvidence(['session']),
            metadata: ['csrf_token' => 'secret'],
        );
    }

    public function testAssuranceMethodsAreAnOwnedSnapshotOfThePolicy(): void
    {
        $method = 'webauthn';
        $requirement = new AssuranceRequirement(requiredMethods: [&$method]);
        $method = 'password';
        $now = new DateTimeImmutable('2030-01-01T00:10:00+00:00');

        self::assertTrue($requirement->isSatisfiedBy(
            self::session(new AuthenticationEvidence(['webauthn'])),
            $now,
        ));
        self::assertFalse($requirement->isSatisfiedBy(
            self::session(new AuthenticationEvidence(['password'])),
            $now,
        ));
    }

    public function testMetadataRetainsValidatedValuesAfterCallerReferencesChange(): void
    {
        $device = 'Browser';
        $remembered = false;
        $session = self::session(
            new AuthenticationEvidence(['password']),
            metadata: ['device' => &$device, 'remembered' => &$remembered],
        );

        $device = new \stdClass();
        $remembered = true;

        self::assertSame(['device' => 'Browser', 'remembered' => false], $session->metadata);
    }

    public function testAssuranceCapabilitiesAreAnOwnedSnapshotOfThePolicy(): void
    {
        $capability = 'phishing_resistant';
        $requirement = new AssuranceRequirement(requiredCapabilities: [&$capability]);
        $capability = 'knowledge';
        $now = new DateTimeImmutable('2030-01-01T00:10:00+00:00');

        self::assertTrue($requirement->isSatisfiedBy(
            self::session(new AuthenticationEvidence(['webauthn'], ['phishing_resistant'])),
            $now,
        ));
        self::assertFalse($requirement->isSatisfiedBy(
            self::session(new AuthenticationEvidence(['password'], ['knowledge'])),
            $now,
        ));
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
