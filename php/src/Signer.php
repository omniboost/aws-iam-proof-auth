<?php

declare(strict_types=1);

namespace Omniboost\AwsIamProof;

use Aws\Credentials\CredentialProvider;
use Aws\Credentials\CredentialsInterface;
use Aws\Signature\SignatureV4;
use GuzzleHttp\Psr7\Request;

/**
 * Makes AWS-IAM-PROOF Authorization headers from AWS credentials.
 *
 * Each header carries its own nonce and is good for exactly one request, so ask
 * for a new one per request (GuzzleMiddleware and the Laravel Http macro do).
 */
final class Signer
{
    /** @var callable(): \GuzzleHttp\Promise\PromiseInterface */
    private $credentials;

    private readonly string $region;

    /**
     * @param callable|null $credentials an AWS SDK credential provider; null uses
     *                                   the default chain (environment, shared
     *                                   config and SSO, container and instance roles)
     * @param string|null   $region      STS region to sign for; null reads
     *                                   AWS_REGION, then AWS_DEFAULT_REGION, then
     *                                   falls back to us-east-1
     */
    public function __construct(
        ?callable $credentials = null,
        ?string $region = null,
        private readonly int $expires = Protocol::DEFAULT_EXPIRY,
    ) {
        if ($expires < 1 || $expires > Protocol::MAX_VALIDITY) {
            throw new \InvalidArgumentException(sprintf(
                'expires must be between 1 and %d seconds, got %d', Protocol::MAX_VALIDITY, $expires,
            ));
        }

        $this->credentials = $credentials ?? CredentialProvider::defaultProvider();
        $this->region = $region
            ?: (getenv('AWS_REGION') ?: (getenv('AWS_DEFAULT_REGION') ?: 'us-east-1'));
    }

    /**
     * Returns a fresh "AWS-IAM-PROOF <proof>" Authorization header value.
     */
    public function header(): string
    {
        return Protocol::AUTH_SCHEME . ' ' . self::base64UrlEncode($this->presignedUrl());
    }

    /**
     * Returns a presigned STS GetCallerIdentity URL carrying a fresh nonce.
     */
    public function presignedUrl(): string
    {
        $query = http_build_query([
            'Action' => 'GetCallerIdentity',
            'Version' => '2011-06-15',
            // In the query before signing, so the signature covers it.
            Protocol::NONCE_PARAM => bin2hex(random_bytes(16)),
        ], '', '&', PHP_QUERY_RFC3986);

        $request = new Request('GET', sprintf('https://sts.%s.amazonaws.com/?%s', $this->region, $query));

        /** @var CredentialsInterface $credentials */
        $credentials = ($this->credentials)()->wait();

        $signed = (new SignatureV4('sts', $this->region))
            ->presign($request, $credentials, sprintf('+%d seconds', $this->expires));

        return (string) $signed->getUri();
    }

    public function region(): string
    {
        return $this->region;
    }

    /**
     * URL-safe base64 with padding, the encoding Go's base64.URLEncoding uses.
     */
    private static function base64UrlEncode(string $value): string
    {
        return strtr(base64_encode($value), '+/', '-_');
    }
}
