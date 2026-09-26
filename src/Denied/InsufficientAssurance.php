<?php

declare(strict_types=1);

namespace Componenta\Auth\Session\Denied;

use Componenta\Auth\DeniedReasonInterface;

final readonly class InsufficientAssurance implements DeniedReasonInterface
{
    public string $code {
        get => 'insufficient_assurance';
    }

    /** @var array<string, mixed> */
    public array $attributes {
        get => [];
    }
}
