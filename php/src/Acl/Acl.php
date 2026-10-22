<?php

declare(strict_types=1);

namespace Omniboost\AwsIamProof\Acl;

use Omniboost\AwsIamProof\Principal;

final class Acl
{
    /**
     * Reports whether the principal has been granted the exact permission.
     */
    public static function allows(AclStore $store, Principal $principal, string $permission): bool
    {
        return in_array($permission, $store->permissions($principal->accountId, $principal->role), true);
    }

    private function __construct()
    {
    }
}
