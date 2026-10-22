<?php

declare(strict_types=1);

namespace Omniboost\AwsIamProof\Tests;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\Uri;
use Omniboost\AwsIamProof\Exception\InfrastructureException;
use Omniboost\AwsIamProof\Exception\InvalidProofException;
use Omniboost\AwsIamProof\Nonce\ArrayNonceStore;
use Omniboost\AwsIamProof\Nonce\NonceStore;
use Omniboost\AwsIamProof\Verifier;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class VerifierTest extends TestCase
{
    public const ARN = 'arn:aws:sts::123456789012:assumed-role/MyRole/my-session';

    /** @var list<array{request: \Psr\Http\Message\RequestInterface}> */
    private array $stsRequests = [];

    public static function identityXml(string $arn = self::ARN): string
    {
        return '<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">'
            . '<GetCallerIdentityResult><Arn>' . $arn . '</Arn>'
            . '<UserId>AROAEXAMPLE:my-session</UserId><Account>123456789012</Account>'
            . '</GetCallerIdentityResult></GetCallerIdentityResponse>';
    }

    public static function header(string $nonce, ?int $signedAt = null): string
    {
        $date = gmdate('Ymd\THis\Z', $signedAt ?? time());
        $url = "https://sts.amazonaws.com/?Action=GetCallerIdentity&X-Amz-Date={$date}&X-Amz-Expires=60&X-Amz-Nonce={$nonce}";

        return 'AWS-IAM-PROOF ' . strtr(base64_encode($url), '+/', '-_');
    }

    /**
     * @param list<Response|\Throwable> $responses
     */
    private function verifier(array $responses, ?NonceStore $nonces = new ArrayNonceStore()): Verifier
    {
        $stack = HandlerStack::create(new MockHandler($responses));
        $stack->push(Middleware::history($this->stsRequests));

        return new Verifier($nonces, new Client(['handler' => $stack]));
    }

    public function testVerifySuccess(): void
    {
        $principal = $this->verifier([new Response(200, [], self::identityXml())])->verify(self::header('n-1'));

        self::assertSame('123456789012', $principal->accountId);
        self::assertSame('MyRole', $principal->role);
        self::assertSame('my-session', $principal->session);
        self::assertCount(1, $this->stsRequests);
        self::assertSame('sts.amazonaws.com', $this->stsRequests[0]['request']->getUri()->getHost());
    }

    public function testXmlWithoutNamespace(): void
    {
        $xml = '<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>' . self::ARN
            . '</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>';

        $principal = $this->verifier([new Response(200, [], $xml)])->verify(self::header('n-1'));

        self::assertSame('MyRole', $principal->role);
    }

    public function testReplayedNonceIsRejectedBeforeSts(): void
    {
        $verifier = $this->verifier([new Response(200, [], self::identityXml())]);
        $verifier->verify(self::header('reused'));

        try {
            $verifier->verify(self::header('reused'));
            self::fail('a replayed nonce was accepted');
        } catch (InvalidProofException $e) {
            self::assertStringContainsString('already been used', $e->getMessage());
        }
        self::assertCount(1, $this->stsRequests, 'STS must not be called for a replayed nonce');
    }

    public function testNonceStoreFailureIsInfrastructure(): void
    {
        $failing = new class implements NonceStore {
            public function use(string $nonce): bool
            {
                throw new RuntimeException('redis unreachable');
            }
        };

        $this->expectException(InfrastructureException::class);
        $this->verifier([], $failing)->verify(self::header('n'));
    }

    public function testInvalidHeaderShortCircuits(): void
    {
        $this->expectException(InvalidProofException::class);
        try {
            $this->verifier([])->verify('Bearer nope');
        } finally {
            self::assertCount(0, $this->stsRequests);
        }
    }

    public function testSts403IsInvalidProof(): void
    {
        $this->expectException(InvalidProofException::class);
        $this->verifier([new Response(403, [], 'AccessDenied')])->verify(self::header('n'));
    }

    public function testSts5xxIsInfrastructure(): void
    {
        $this->expectException(InfrastructureException::class);
        $this->verifier([new Response(503, [], 'unavailable')])->verify(self::header('n'));
    }

    public function testStsUnreachableIsInfrastructure(): void
    {
        $this->expectException(InfrastructureException::class);
        $this->verifier([new ConnectException('refused', new Request('GET', 'https://sts.amazonaws.com'))])
            ->verify(self::header('n'));
    }

    public function testUnparseableStsBodyIsInfrastructure(): void
    {
        $this->expectException(InfrastructureException::class);
        $this->verifier([new Response(200, [], 'not xml')])->verify(self::header('n'));
    }

    public function testRedirectIsNotFollowed(): void
    {
        $this->expectException(InvalidProofException::class);
        $this->verifier([
            new Response(302, ['Location' => 'https://evil.example.com/']),
            new Response(200, [], self::identityXml()),
        ])->verify(self::header('n'));
    }

    public function testNonAssumedRoleArnIsRejected(): void
    {
        $this->expectException(InvalidProofException::class);
        $this->verifier([new Response(200, [], self::identityXml('arn:aws:iam::123456789012:user/bob'))])
            ->verify(self::header('n'));
    }

    public function testNullStoreSkipsReplayCheck(): void
    {
        $verifier = $this->verifier([
            new Response(200, [], self::identityXml()),
            new Response(200, [], self::identityXml()),
        ], null);

        $verifier->verify(self::header('same'));
        $verifier->verify(self::header('same'));
        self::assertCount(2, $this->stsRequests);
    }

    /**
     * @return iterable<string, array{string, string|null}>
     */
    public static function authorizationHeaders(): iterable
    {
        $url = 'https://sts.amazonaws.com/?a=~~~';
        yield 'url-safe padded' => ['AWS-IAM-PROOF ' . strtr(base64_encode($url), '+/', '-_'), $url];
        yield 'standard alphabet' => ['AWS-IAM-PROOF ' . base64_encode($url), $url];
        yield 'url-safe unpadded' => ['AWS-IAM-PROOF ' . rtrim(strtr(base64_encode($url), '+/', '-_'), '='), $url];
        yield 'surrounding whitespace' => ['  AWS-IAM-PROOF ' . base64_encode($url) . '  ', $url];
        yield 'wrong scheme' => ['Bearer ' . base64_encode($url), null];
        yield 'missing proof' => ['AWS-IAM-PROOF', null];
        yield 'empty proof' => ['AWS-IAM-PROOF ', null];
        yield 'invalid base64' => ['AWS-IAM-PROOF not-valid-base64!!!', null];
    }

    #[DataProvider('authorizationHeaders')]
    public function testParseAuthorization(string $header, ?string $want): void
    {
        if ($want === null) {
            $this->expectException(InvalidProofException::class);
        }

        self::assertSame($want, (string) Verifier::parseAuthorization($header));
    }

    /**
     * The cases shared with the Go verifier (testdata/proof/urls.json).
     *
     * @return iterable<string, array{string, string|null, int}>
     */
    public static function sharedUrlCases(): iterable
    {
        $vectors = json_decode((string) file_get_contents(__DIR__ . '/../../testdata/proof/urls.json'), true, flags: JSON_THROW_ON_ERROR);
        $now = (new \DateTimeImmutable($vectors['now']))->getTimestamp();
        foreach ($vectors['cases'] as $case) {
            yield $case['name'] => [$case['url'], $case['nonce'], $now];
        }
    }

    #[DataProvider('sharedUrlCases')]
    public function testValidatePresignedUrl(string $url, ?string $nonce, int $now): void
    {
        if ($nonce === null) {
            $this->expectException(InvalidProofException::class);
        }

        self::assertSame($nonce, Verifier::validatePresignedUrl(new Uri($url), $now));
    }
}
