<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

enum RotationReason: string
{
    case Reauthentication = 'reauthentication';
    case PrivilegeChange = 'privilege_change';
    case SecurityEvent = 'security_event';
}
