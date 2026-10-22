<?php

declare(strict_types=1);

namespace Omniboost\AwsIamProof\Acl;

use InvalidArgumentException;
use JsonException;

/**
 * ACL store from a fixed list of grants, in the same format the Go acl package
 * reads from AWS_IAM_PROOF_ACL:
 *
 *     [{"account_id": "123456789012", "role": "Developer", "permissions": ["pipelines.view"]}]
 *
 * Parsing is strict, because a typo here silently denies access.
 */
final class ArrayAclStore implements AclStore
{
    public const ENV_VAR = 'AWS_IAM_PROOF_ACL';

    private const FIELDS = ['account_id', 'role', 'permissions'];

    /** @var array<string, list<string>> "account|role" => permissions */
    private array $grants = [];

    /**
     * @param list<array{account_id: string, role: string, permissions: list<string>}> $grants
     *
     * @throws InvalidArgumentException on a malformed grant
     */
    public function __construct(array $grants = [])
    {
        if (!array_is_list($grants)) {
            throw new InvalidArgumentException('acl: grants must be a list');
        }
        foreach ($grants as $i => $grant) {
            self::validate($i, $grant);
            $key = $grant['account_id'] . '|' . $grant['role'];
            $this->grants[$key] = [...($this->grants[$key] ?? []), ...$grant['permissions']];
        }
    }

    /**
     * @throws InvalidArgumentException on invalid JSON or a malformed grant
     */
    public static function fromJson(string $json): self
    {
        try {
            $grants = json_decode($json, true, 16, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new InvalidArgumentException('acl: decode grants: ' . $e->getMessage(), 0, $e);
        }
        if (!is_array($grants)) {
            throw new InvalidArgumentException('acl: grants must be a JSON array');
        }

        return new self($grants);
    }

    /**
     * Builds the store from the AWS_IAM_PROOF_ACL environment variable, or
     * returns null when it is unset or blank.
     *
     * @throws InvalidArgumentException when the variable holds malformed grants
     */
    public static function fromEnv(): ?self
    {
        $raw = getenv(self::ENV_VAR);
        if ($raw === false || trim($raw) === '') {
            return null;
        }

        try {
            return self::fromJson($raw);
        } catch (InvalidArgumentException $e) {
            throw new InvalidArgumentException(self::ENV_VAR . ': ' . $e->getMessage(), 0, $e);
        }
    }

    public function permissions(string $accountId, string $role): array
    {
        return $this->grants[$accountId . '|' . $role] ?? [];
    }

    private static function validate(int $i, mixed $grant): void
    {
        if (!is_array($grant) || array_is_list($grant) && $grant !== []) {
            throw new InvalidArgumentException(sprintf('acl: grant %d is not an object', $i));
        }
        if ($unknown = array_diff(array_keys($grant), self::FIELDS)) {
            throw new InvalidArgumentException(sprintf('acl: grant %d: unknown field "%s"', $i, implode('", "', $unknown)));
        }

        $accountId = $grant['account_id'] ?? null;
        if (!is_string($accountId) || preg_match('/^[0-9]{12}$/', $accountId) !== 1) {
            throw new InvalidArgumentException(sprintf('acl: grant %d: account_id is not a 12-digit AWS account ID', $i));
        }

        $role = $grant['role'] ?? null;
        if (!is_string($role) || $role === '') {
            throw new InvalidArgumentException(sprintf('acl: grant %d: role is empty', $i));
        }

        $permissions = $grant['permissions'] ?? [];
        if (!is_array($permissions) || !array_is_list($permissions)) {
            throw new InvalidArgumentException(sprintf('acl: grant %d: permissions must be a list', $i));
        }
        foreach ($permissions as $permission) {
            if (!is_string($permission) || trim($permission) === '') {
                throw new InvalidArgumentException(sprintf('acl: grant %d: empty permission', $i));
            }
        }
    }
}
