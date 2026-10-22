<?php

declare(strict_types=1);

namespace Omniboost\AwsIamProof\Tests;

use InvalidArgumentException;
use Omniboost\AwsIamProof\Acl\Acl;
use Omniboost\AwsIamProof\Acl\ArrayAclStore;
use Omniboost\AwsIamProof\Nonce\ArrayNonceStore;
use Omniboost\AwsIamProof\Principal;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class AclTest extends TestCase
{
    private const TESTDATA = __DIR__ . '/../../testdata/acl/';

    protected function tearDown(): void
    {
        putenv(ArrayAclStore::ENV_VAR);
    }

    public function testSharedValidGrantsMerge(): void
    {
        $store = ArrayAclStore::fromJson((string) file_get_contents(self::TESTDATA . 'valid.json'));

        self::assertSame(['pipelines.view', 'pipelines.edit', 'pipelines.delete'], $store->permissions('123456789012', 'Developer'));
        self::assertSame([], $store->permissions('210987654321', 'Reader'));
        self::assertSame([], $store->permissions('123456789012', 'Reader'));
    }

    /**
     * The invalid inputs shared with the Go tests.
     *
     * @return iterable<string, array{string}>
     */
    public static function invalidGrants(): iterable
    {
        $cases = json_decode((string) file_get_contents(self::TESTDATA . 'invalid.json'), true, flags: JSON_THROW_ON_ERROR);
        foreach ($cases as $name => $input) {
            yield $name => [$input];
        }
    }

    #[DataProvider('invalidGrants')]
    public function testRejects(string $json): void
    {
        $this->expectException(InvalidArgumentException::class);
        ArrayAclStore::fromJson($json);
    }

    public function testAllows(): void
    {
        $store = new ArrayAclStore([['account_id' => '123456789012', 'role' => 'Dev', 'permissions' => ['a']]]);
        $principal = new Principal('123456789012', 'Dev', 's', 'arn');

        self::assertTrue(Acl::allows($store, $principal, 'a'));
        self::assertFalse(Acl::allows($store, $principal, 'b'));
        self::assertFalse(Acl::allows($store, new Principal('123456789012', 'Other', 's', 'arn'), 'a'));
    }

    public function testFromEnv(): void
    {
        putenv(ArrayAclStore::ENV_VAR . '=[{"account_id": "123456789012", "role": "Dev", "permissions": ["a"]}]');

        self::assertSame(['a'], ArrayAclStore::fromEnv()?->permissions('123456789012', 'Dev'));
    }

    public function testFromEnvUnset(): void
    {
        self::assertNull(ArrayAclStore::fromEnv());
        putenv(ArrayAclStore::ENV_VAR . '=  ');
        self::assertNull(ArrayAclStore::fromEnv());
    }

    public function testFromEnvInvalidNamesTheVariable(): void
    {
        putenv(ArrayAclStore::ENV_VAR . '=nope');

        $this->expectExceptionMessage(ArrayAclStore::ENV_VAR);
        ArrayAclStore::fromEnv();
    }

    public function testArrayNonceStoreExpires(): void
    {
        $now = 1000;
        $store = new ArrayNonceStore(300, static function () use (&$now): int {
            return $now;
        });

        self::assertTrue($store->use('n'));
        self::assertFalse($store->use('n'));
        $now += 300;
        self::assertTrue($store->use('n'));
    }
}
