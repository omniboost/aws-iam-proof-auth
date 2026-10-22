<?php

declare(strict_types=1);

namespace Omniboost\AwsIamProof;

use Closure;
use DateTimeImmutable;
use DateTimeZone;
use DOMDocument;
use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Uri;
use GuzzleHttp\RequestOptions;
use Omniboost\AwsIamProof\Exception\InfrastructureException;
use Omniboost\AwsIamProof\Exception\InvalidProofException;
use Omniboost\AwsIamProof\Nonce\NonceStore;
use Throwable;

/**
 * Turns an AWS-IAM-PROOF Authorization header into a verified Principal. The
 * checks match the Go Verifier (verifier.go, proof.go) one for one.
 */
final class Verifier
{
    private const AMZ_DATE_FORMAT = 'Ymd\THis\Z';

    private readonly ClientInterface $http;

    private readonly Closure $now;

    /**
     * @param NonceStore|null      $nonces shared nonce store; null disables replay
     *                                     protection, which is only acceptable in tests
     * @param ClientInterface|null $http   client used to call STS; null builds one
     *                                     with a 10 second timeout
     * @param Closure|null         $now    returns the current unix time; for tests
     */
    public function __construct(
        private readonly ?NonceStore $nonces,
        ?ClientInterface $http = null,
        ?Closure $now = null,
    ) {
        $this->http = $http ?? new Client([RequestOptions::TIMEOUT => 10]);
        $this->now = $now ?? static fn (): int => time();
    }

    /**
     * @throws InvalidProofException   the proof is invalid, expired or replayed
     * @throws InfrastructureException the nonce store or STS failed
     */
    public function verify(string $authorization): Principal
    {
        $uri = self::parseAuthorization($authorization);
        $nonce = self::validatePresignedUrl($uri, ($this->now)());

        if ($this->nonces !== null) {
            try {
                $fresh = $this->nonces->use($nonce);
            } catch (Throwable $e) {
                throw new InfrastructureException('check nonce: ' . $e->getMessage(), 0, $e);
            }
            if (!$fresh) {
                throw new InvalidProofException(sprintf('nonce "%s" has already been used', $nonce));
            }
        }

        return Principal::fromCallerArn($this->fetchCallerArn($uri));
    }

    /**
     * Extracts the presigned STS URL from "AWS-IAM-PROOF <base64>". Both base64
     * alphabets are accepted, padded or not.
     *
     * @throws InvalidProofException
     */
    public static function parseAuthorization(string $header): Uri
    {
        $parts = explode(' ', trim($header), 2);
        if (count($parts) !== 2 || $parts[0] !== Protocol::AUTH_SCHEME) {
            throw new InvalidProofException(sprintf('authorization header must use the %s scheme', Protocol::AUTH_SCHEME));
        }

        $decoded = base64_decode(strtr(rtrim($parts[1], '='), '-_', '+/'), true);
        if ($decoded === false || $parts[1] === '') {
            throw new InvalidProofException('decode proof: invalid base64');
        }

        try {
            return new Uri($decoded);
        } catch (Throwable $e) {
            throw new InvalidProofException('parse presigned url: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Checks the URL targets STS GetCallerIdentity over https, is short-lived
     * and fresh, and carries a nonce, which it returns.
     *
     * @throws InvalidProofException
     */
    public static function validatePresignedUrl(Uri $uri, int $now): string
    {
        if ($uri->getScheme() !== 'https') {
            throw new InvalidProofException(sprintf('presigned url scheme "%s" is not https', $uri->getScheme()));
        }

        $query = self::parseQuery($uri->getQuery());

        if (($query[Protocol::ACTION_PARAM] ?? '') !== 'GetCallerIdentity') {
            throw new InvalidProofException('presigned url action must be GetCallerIdentity');
        }

        $host = $uri->getHost();
        if ((!str_ends_with($host, '.amazonaws.com') && !str_ends_with($host, '.api.aws'))
            || (!str_starts_with($host, 'sts.') && !str_starts_with($host, 'sts-fips.'))) {
            throw new InvalidProofException(sprintf('presigned url host "%s" is not a valid STS endpoint', $host));
        }

        self::validateValidityWindow($query, $now);

        $nonce = $query[Protocol::NONCE_PARAM] ?? '';
        if ($nonce === '') {
            throw new InvalidProofException('presigned url is missing a nonce');
        }

        return $nonce;
    }

    /**
     * @param array<string, string> $query
     *
     * @throws InvalidProofException
     */
    private static function validateValidityWindow(array $query, int $now): void
    {
        $expires = $query[Protocol::EXPIRES_PARAM] ?? '';
        if ($expires === '') {
            throw new InvalidProofException('presigned url is missing X-Amz-Expires');
        }
        if (preg_match('/^[0-9]+$/', $expires) !== 1 || (int) $expires <= 0) {
            throw new InvalidProofException(sprintf('presigned url has invalid X-Amz-Expires "%s"', $expires));
        }
        // Check the length before casting: a value too long for an int would
        // saturate instead of failing.
        if (strlen(ltrim($expires, '0')) > 6 || (int) $expires > Protocol::MAX_VALIDITY) {
            throw new InvalidProofException(sprintf('presigned url validity %ss exceeds the %ds maximum', $expires, Protocol::MAX_VALIDITY));
        }

        $date = $query[Protocol::DATE_PARAM] ?? '';
        if ($date === '') {
            throw new InvalidProofException('presigned url is missing X-Amz-Date');
        }
        $signedAt = DateTimeImmutable::createFromFormat('!' . self::AMZ_DATE_FORMAT, $date, new DateTimeZone('UTC'));
        if ($signedAt === false || $signedAt->format(self::AMZ_DATE_FORMAT) !== $date) {
            throw new InvalidProofException(sprintf('presigned url has invalid X-Amz-Date "%s"', $date));
        }
        $age = $now - $signedAt->getTimestamp();
        if ($age > Protocol::NONCE_TTL) {
            throw new InvalidProofException(sprintf('presigned url signed %ds ago exceeds the %ds freshness window', $age, Protocol::NONCE_TTL));
        }
    }

    /**
     * Parses a query string the way Go's url.Values.Get sees it: the first
     * value per key wins, and '+' decodes to a space.
     *
     * @return array<string, string>
     */
    private static function parseQuery(string $query): array
    {
        $values = [];
        foreach (explode('&', $query) as $pair) {
            if ($pair === '' || str_contains($pair, ';')) {
                continue;
            }
            [$key, $value] = array_pad(explode('=', $pair, 2), 2, '');
            $key = urldecode($key);
            if (!array_key_exists($key, $values)) {
                $values[$key] = urldecode($value);
            }
        }

        return $values;
    }

    /**
     * Calls the presigned URL and returns the caller's ARN.
     *
     * @throws InvalidProofException   STS rejected the proof
     * @throws InfrastructureException STS could not be reached or failed
     */
    private function fetchCallerArn(Uri $uri): string
    {
        try {
            $response = $this->http->send(new Request('GET', $uri), [
                RequestOptions::HTTP_ERRORS => false,
                // The URL was checked to point at STS; do not let a response
                // send the request anywhere else.
                RequestOptions::ALLOW_REDIRECTS => false,
            ]);
        } catch (GuzzleException $e) {
            throw new InfrastructureException('execute request: ' . $e->getMessage(), 0, $e);
        }

        $status = $response->getStatusCode();
        $body = (string) $response->getBody();
        if ($status !== 200) {
            $message = sprintf('sts returned %d: %s', $status, trim($body));
            if ($status >= 500) {
                throw new InfrastructureException($message);
            }
            throw new InvalidProofException($message);
        }

        $arn = self::parseCallerArn($body);
        if ($arn === null) {
            throw new InfrastructureException('decode GetCallerIdentityResponse XML: unexpected body');
        }

        return $arn;
    }

    private static function parseCallerArn(string $xml): ?string
    {
        if ($xml === '') {
            return null;
        }

        $doc = new DOMDocument();
        $previous = libxml_use_internal_errors(true);
        try {
            $loaded = $doc->loadXML($xml, LIBXML_NONET);
        } finally {
            libxml_clear_errors();
            libxml_use_internal_errors($previous);
        }
        if (!$loaded || $doc->documentElement?->localName !== 'GetCallerIdentityResponse') {
            return null;
        }

        $arn = $doc->getElementsByTagNameNS('*', 'Arn')->item(0);

        return $arn?->textContent;
    }
}
