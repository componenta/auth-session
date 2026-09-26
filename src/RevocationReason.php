<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

enum RevocationReason: string
{
    case Logout = 'logout';
    case UserRequested = 'user_requested';
    case AdministratorRequested = 'administrator_requested';
    case AccountDisabled = 'account_disabled';
    case CredentialCompromise = 'credential_compromise';
    case Superseded = 'superseded';
    case SecurityEvent = 'security_event';
}
