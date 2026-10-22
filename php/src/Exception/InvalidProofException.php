<?php

declare(strict_types=1);

namespace Omniboost\AwsIamProof\Exception;

/**
 * The proof is malformed, expired, replayed or rejected by STS: a client error.
 */
final class InvalidProofException extends VerificationException
{
}
