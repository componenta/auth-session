<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Tests;

use Componenta\Auth\Session\SessionCredential;
use PHPUnit\Framework\TestCase;

final class SessionCredentialTest extends TestCase
{
    public function testGeneratesOpaque256BitWireCredential(): void
    {
        $credential = SessionCredential::generate()->toString();

        self::assertSame(43, strlen($credential));
        self::assertMatchesRegularExpression('/\A[A-Za-z0-9_-]{43}\z/D', $credential);
    }

    public function testRejectsMalformedWireCredential(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        SessionCredential::fromString('attacker-controlled');
    }

    public function testDebugOutputNeverContainsBearer(): void
    {
        $credential = SessionCredential::fromBytes(str_repeat('a', 32));

        self::assertSame(
            ['credential' => '[REDACTED]'],
            $credential->__debugInfo(),
        );
    }
}
