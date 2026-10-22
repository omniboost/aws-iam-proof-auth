<?php

declare(strict_types=1);

namespace Omniboost\AwsIamProof\Tests;

use Aws\Credentials\CredentialProvider;
use Aws\Credentials\Credentials;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use Omniboost\AwsIamProof\GuzzleMiddleware;
use Omniboost\AwsIamProof\Signer;
use Omniboost\AwsIamProof\Verifier;
use PHPUnit\Framework\TestCase;

final class SignerTest extends TestCase
{
    /**
     * Throwaway keys: presigning never leaves the process.
     */
    public static function signer(string $region = 'eu-west-1'): Signer
    {
        return new Signer(
            CredentialProvider::fromCredentials(new Credentials('AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')),
            $region,
        );
    }

    public function testPresignedUrlShape(): void
    {
        $url = self::signer()->presignedUrl();
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

        self::assertStringStartsWith('https://sts.eu-west-1.amazonaws.com/?', $url);
        self::assertSame('GetCallerIdentity', $query['Action']);
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $query['X-Amz-Nonce']);
        self::assertSame('60', $query['X-Amz-Expires']);
        self::assertNotEmpty($query['X-Amz-Signature']);
    }

    public function testHeaderPassesTheVerifiersChecks(): void
    {
        $uri = Verifier::parseAuthorization(self::signer()->header());

        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/', Verifier::validatePresignedUrl($uri, time()));
    }

    public function testHeaderIsUrlSafeBase64(): void
    {
        $header = self::signer()->header();

        self::assertStringStartsWith('AWS-IAM-PROOF ', $header);
        self::assertDoesNotMatchRegularExpression('#[+/]#', substr($header, strlen('AWS-IAM-PROOF ')));
    }

    public function testEveryHeaderHasItsOwnNonce(): void
    {
        $signer = self::signer();

        self::assertNotSame($signer->header(), $signer->header());
    }

    public function testExpiryIsBounded(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new Signer(region: 'eu-west-1', expires: 3600);
    }

    public function testGuzzleMiddlewareSignsEveryRequest(): void
    {
        $history = [];
        $stack = HandlerStack::create(new MockHandler([new Response(200), new Response(200)]));
        $stack->push(GuzzleMiddleware::sign(self::signer()));
        $stack->push(Middleware::history($history));
        $client = new Client(['handler' => $stack]);

        $client->get('https://api.example.test/a');
        $client->get('https://api.example.test/b');

        $first = $history[0]['request']->getHeaderLine('Authorization');
        $second = $history[1]['request']->getHeaderLine('Authorization');
        self::assertStringStartsWith('AWS-IAM-PROOF ', $first);
        self::assertNotSame($first, $second);
    }
}
