<?php

declare(strict_types=1);

namespace Omniboost\AwsIamProof;

/**
 * Wire constants shared with the Go implementation (iamproof.go). Changing one
 * here without changing it there breaks interoperability.
 */
final class Protocol
{
    public const AUTH_SCHEME = 'AWS-IAM-PROOF';

    public const NONCE_PARAM = 'X-Amz-Nonce';
    public const EXPIRES_PARAM = 'X-Amz-Expires';
    public const DATE_PARAM = 'X-Amz-Date';
    public const ACTION_PARAM = 'Action';

    /** Seconds a proof made by Signer stays valid at STS. */
    public const DEFAULT_EXPIRY = 60;

    /**
     * Longest X-Amz-Expires the verifier accepts. It must stay below
     * NONCE_TTL, or a proof could outlive its nonce and be replayed.
     */
    public const MAX_VALIDITY = 120;

    /** Seconds a nonce store must remember a nonce. */
    public const NONCE_TTL = 300;

    private function __construct()
    {
    }
}
