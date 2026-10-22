<?php

declare(strict_types=1);

namespace Omniboost\AwsIamProof;

use JsonSerializable;
use Omniboost\AwsIamProof\Exception\InvalidProofException;

/**
 * The verified identity behind a request.
 */
final class Principal implements JsonSerializable
{
    public function __construct(
        public readonly string $accountId,
        public readonly string $role,
        public readonly string $session,
        public readonly string $arn,
    ) {
    }

    /**
     * Parses an assumed-role STS ARN such as
     * arn:aws:sts::123456789012:assumed-role/Developer/alice. An SSO role
     * name (AWSReservedSSO_<name>_<hash>) is reduced to <name>.
     *
     * @throws InvalidProofException when the ARN is not an assumed-role STS ARN
     */
    public static function fromCallerArn(string $arn): self
    {
        $parts = explode(':', $arn, 6);
        if (count($parts) !== 6 || $parts[0] !== 'arn' || $parts[1] === '' || $parts[4] === '') {
            throw new InvalidProofException(sprintf("failed to parse arn '%s'", $arn));
        }
        [, , $service, , $accountId, $resource] = $parts;

        if ($service !== 'sts') {
            throw new InvalidProofException(sprintf("arn '%s' is not 'sts'", $arn));
        }

        $resourceParts = explode('/', $resource, 3);
        if (count($resourceParts) !== 3 || $resourceParts[0] !== 'assumed-role') {
            throw new InvalidProofException('unexpected arn format');
        }

        return new self($accountId, self::normalizeRole($resourceParts[1]), $resourceParts[2], $arn);
    }

    public static function normalizeRole(string $role): string
    {
        if (preg_match('/^AWSReservedSSO_(.+?)_[a-f0-9]+$/', $role, $matches) === 1) {
            return $matches[1];
        }

        return $role;
    }

    /**
     * Same field names as the Go Principal's JSON.
     *
     * @return array{account_id: string, role: string, session: string, arn: string}
     */
    public function jsonSerialize(): array
    {
        return [
            'account_id' => $this->accountId,
            'role' => $this->role,
            'session' => $this->session,
            'arn' => $this->arn,
        ];
    }
}
