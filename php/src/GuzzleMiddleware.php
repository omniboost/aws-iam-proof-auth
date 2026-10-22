<?php

declare(strict_types=1);

namespace Omniboost\AwsIamProof;

use GuzzleHttp\Middleware;
use Psr\Http\Message\RequestInterface;

/**
 * Guzzle middleware that adds a fresh AWS-IAM-PROOF header to every request,
 * retries included.
 *
 *     $stack = HandlerStack::create();
 *     $stack->push(GuzzleMiddleware::sign(new Signer()));
 *     $client = new Client(['handler' => $stack]);
 */
final class GuzzleMiddleware
{
    public static function sign(Signer $signer): callable
    {
        return Middleware::mapRequest(
            static fn (RequestInterface $request): RequestInterface => $request->withHeader('Authorization', $signer->header()),
        );
    }
}
