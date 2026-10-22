<?php

declare(strict_types=1);

namespace Omniboost\AwsIamProof\Tests;

use Omniboost\AwsIamProof\Exception\InvalidProofException;
use Omniboost\AwsIamProof\Principal;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PrincipalTest extends TestCase
{
    public function testAssumedRole(): void
    {
        $arn = 'arn:aws:sts::123456789012:assumed-role/MyRole/my-session';

        self::assertEquals(new Principal('123456789012', 'MyRole', 'my-session', $arn), Principal::fromCallerArn($arn));
    }

    public function testSsoRoleIsNormalized(): void
    {
        $principal = Principal::fromCallerArn('arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_AdminAccess_0123abcd4567ef89/alice');

        self::assertSame('AdminAccess', $principal->role);
        self::assertSame('alice', $principal->session);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function invalidArns(): iterable
    {
        yield 'non-sts service' => ['arn:aws:iam::123456789012:user/bob'];
        yield 'not an assumed role' => ['arn:aws:sts::123456789012:federated-user/bob'];
        yield 'malformed' => ['not-an-arn'];
    }

    #[DataProvider('invalidArns')]
    public function testRejects(string $arn): void
    {
        $this->expectException(InvalidProofException::class);
        Principal::fromCallerArn($arn);
    }

    /**
     * @return iterable<array{string, string}>
     */
    public static function roles(): iterable
    {
        yield ['PlainRole', 'PlainRole'];
        yield ['AWSReservedSSO_AdminAccess_0123abcd4567ef89', 'AdminAccess'];
        yield ['AWSReservedSSO_Read_Only_deadbeef', 'Read_Only'];
        yield ['AWSReservedSSO_malformed', 'AWSReservedSSO_malformed'];
    }

    #[DataProvider('roles')]
    public function testNormalizeRole(string $in, string $want): void
    {
        self::assertSame($want, Principal::normalizeRole($in));
    }

    public function testJsonMatchesGo(): void
    {
        $principal = new Principal('1', 'R', 's', 'arn');

        self::assertSame('{"account_id":"1","role":"R","session":"s","arn":"arn"}', json_encode($principal));
    }
}
