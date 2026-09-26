<?php

declare(strict_types=1);

namespace Componenta\Auth\Session;

enum ConcurrentSessionOverflow: string
{
    case RejectNew = 'reject_new';
    case RevokeOldest = 'revoke_oldest';
}
