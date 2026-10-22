<?php

declare(strict_types=1);

namespace Omniboost\AwsIamProof\Acl;

/**
 * Resolves the permissions granted to an AWS account + role.
 */
interface AclStore
{
    /**
     * @return list<string> the granted permissions; empty when there are none
     */
    public function permissions(string $accountId, string $role): array;
}
