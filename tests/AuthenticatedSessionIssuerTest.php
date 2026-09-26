<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Tests;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\Session\AuthenticatedSessionIssuer;
use Componenta\Auth\Session\AuthSession;
use Componenta\Auth\Session\AuthSessionGrant;
use Componenta\Auth\Session\AuthSessionManagerInterface;
use Componenta\Auth\Session\AuthSessionPolicy;
use Componenta\Auth\Session\AuthSessionPolicyProviderInterface;
use Componenta\Auth\Session\RevocationReason;
use Componenta\Auth\Session\RotationReason;
use Componenta\Auth\Session\SessionCredential;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class AuthenticatedSessionIssuerTest extends TestCase
{
    public function testDelegatesInitialSessionCreationThroughPolicyProvider(): void
    {
        $identity = new IssuerIdentityFixture();
        $evidence = new AuthenticationEvidence(['otp.email']);
        $policy = new AuthSessionPolicy(3600, 86400);
        $grant = self::grant($identity->uuid, $evidence, $policy);
        $manager = new RecordingManagerFixture($grant);
        $issuer = new AuthenticatedSessionIssuer(
            $manager,
            new FixedPolicyFixture($policy),
        );

        self::assertSame(
            $grant,
            $issuer->issue($identity, $evidence, ['device' => 'Browser']),
        );
        self::assertNotNull($manager->subjectId);
        self::assertTrue($identity->uuid->equals($manager->subjectId));
        self::assertSame($evidence, $manager->evidence);
        self::assertSame($policy, $manager->policy);
        self::assertSame(['device' => 'Browser'], $manager->metadata);
    }

    private static function grant(
        UuidInterface $subjectId,
        AuthenticationEvidence $evidence,
        AuthSessionPolicy $policy,
    ): AuthSessionGrant {
        $now = new DateTimeImmutable('2030-01-01T00:00:00+00:00');

        return new AuthSessionGrant(
            new AuthSession(
                Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc'),
                $subjectId,
                $evidence,
                1,
                $now,
                $now,
                null,
                $now,
                $now->modify(sprintf('+%d seconds', $policy->idleTimeout)),
                $now->modify(sprintf('+%d seconds', $policy->absoluteTimeout)),
            ),
            SessionCredential::fromBytes(str_repeat('a', 32)),
        );
    }
}

final class IssuerIdentityFixture implements IdentityInterface
{
    public UuidInterface $uuid {
        get => Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abd');
    }
}

final class RecordingManagerFixture implements AuthSessionManagerInterface
{
    public ?UuidInterface $subjectId = null;
    public ?AuthenticationEvidence $evidence = null;
    public ?AuthSessionPolicy $policy = null;

    /** @var array<string, scalar|null> */
    public array $metadata = [];

    public function __construct(private AuthSessionGrant $grant) {}

    public function create(
        UuidInterface $subjectId,
        AuthenticationEvidence $evidence,
        AuthSessionPolicy $policy,
        array $metadata = [],
    ): AuthSessionGrant {
        $this->subjectId = $subjectId;
        $this->evidence = $evidence;
        $this->policy = $policy;
        $this->metadata = $metadata;

        return $this->grant;
    }

    public function resume(SessionCredential $credential): ?AuthSession
    {
        return null;
    }

    public function touch(AuthSession $observed): void {}

    public function rotate(
        AuthSession $observed,
        AuthenticationEvidence $evidence,
        RotationReason $reason,
        ?AuthSessionPolicy $policy = null,
    ): AuthSessionGrant {
        return $this->grant;
    }

    public function revoke(UuidInterface $sessionId, RevocationReason $reason): void {}

    public function revokePresentedCredential(
        SessionCredential $credential,
        RevocationReason $reason,
    ): void {}

    public function revokeAll(
        UuidInterface $subjectId,
        ?UuidInterface $exceptSessionId = null,
        RevocationReason $reason = RevocationReason::UserRequested,
    ): void {}

    public function isGrantCurrent(AuthSessionGrant $grant): bool
    {
        return true;
    }
}

final readonly class FixedPolicyFixture implements AuthSessionPolicyProviderInterface
{
    public function __construct(private AuthSessionPolicy $policy) {}

    public function for(
        IdentityInterface $identity,
        AuthenticationEvidence $evidence,
    ): AuthSessionPolicy {
        return $this->policy;
    }
}
