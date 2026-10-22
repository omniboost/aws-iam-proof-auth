<?php

declare(strict_types=1);

namespace Omniboost\AwsIamProof\Exception;

use RuntimeException;

/**
 * Verification failed. Catch InvalidProofException for client errors and
 * InfrastructureException for failures on the verifying side.
 */
abstract class VerificationException extends RuntimeException
{
}
