<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Tests;

use Componenta\Auth\AuthenticationAdmission;
use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\AuthenticationGuardInterface;
use Componenta\Auth\Denied\DeniedReason;
use Componenta\Auth\IdentityProviderInterface;
use Componenta\Auth\Session\AuthenticatedSessionIssuer;
use Componenta\Auth\Session\AuthSession;
use Componenta\Auth\Session\AuthSessionManagerInterface;
use Componenta\Auth\Session\AuthSessionPolicyProviderInterface;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\UuidFactory;
use Componenta\Identity\UuidInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class IssuanceAdmissionTest extends TestCase
{
    #[DataProvider('operations')]
    public function testDisabledSubjectCannotCreateOrStrengthenCredentials(bool $reauthenticate): void
    {
        $identity = new readonly class((new UuidFactory())->generate()) implements IdentityInterface {
            public function __construct(public UuidInterface $uuid) {}
        };
        $provider = $this->createStub(IdentityProviderInterface::class);
        $provider->method('findByUuid')->willReturn($identity);
        $denial = new DeniedReason('user_disabled');
        $guard = $this->createStub(AuthenticationGuardInterface::class);
        $guard->method('check')->willReturn($denial);
        $manager = $this->createMock(AuthSessionManagerInterface::class);
        $manager->expects(self::never())->method('create');
        $manager->expects(self::never())->method('rotate');
        $policies = $this->createMock(AuthSessionPolicyProviderInterface::class);
        $policies->expects(self::never())->method('for');
        $issuer = new AuthenticatedSessionIssuer($manager, $policies, new AuthenticationAdmission($provider, $guard));
        $proof = new AuthenticationEvidence(['webauthn']);
        $now = new \DateTimeImmutable('2030-01-01T00:00:00+00:00');
        $session = new AuthSession((new UuidFactory())->generate(), $identity->uuid, new AuthenticationEvidence(['password']), 1, $now, null, $now, $now->modify('+1 hour'), $now->modify('+8 hours'));
        $result = $reauthenticate ? $issuer->reauthenticate($session, $identity, $proof) : $issuer->issue($identity, $proof);
        self::assertSame($denial, $result);
    }

    public static function operations(): iterable
    {
        yield 'initial-login' => [false];
        yield 'reauthentication' => [true];
    }
}
