<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Tests;

use Componenta\Auth\Session\PreAuthenticationCredential;
use Componenta\Auth\Session\PreAuthenticationRequestToken;
use PHPUnit\Framework\TestCase;

final class PreAuthenticationValueObjectsTest extends TestCase
{
    public function testCredentialAndRequestTokenAreIndependentOpaqueSecrets(): void
    {
        $credential = PreAuthenticationCredential::generate();
        $requestToken = PreAuthenticationRequestToken::generate();

        self::assertSame(43, strlen($credential->toString()));
        self::assertSame(43, strlen($requestToken->toString()));
        self::assertNotSame($credential->toString(), $requestToken->toString());
        self::assertStringNotContainsString(
            $credential->toString(),
            json_encode($credential->__debugInfo(), JSON_THROW_ON_ERROR),
        );
        self::assertStringNotContainsString(
            $requestToken->toString(),
            json_encode($requestToken->__debugInfo(), JSON_THROW_ON_ERROR),
        );
    }
}
