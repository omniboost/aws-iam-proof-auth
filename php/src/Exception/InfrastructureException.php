<?php

declare(strict_types=1);

namespace Omniboost\AwsIamProof\Exception;

/**
 * Verification could not complete because a dependency failed: the nonce store
 * is unreachable, or STS is down or answered something unexpected. This is a
 * server fault and worth reporting, unlike InvalidProofException.
 */
final class InfrastructureException extends VerificationException
{
}
