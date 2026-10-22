<?php

declare(strict_types=1);

namespace Omniboost\AwsIamProof\Nonce;

/**
 * Remembers nonces so a proof cannot be replayed.
 */
interface NonceStore
{
    /**
     * Records the nonce and returns true if it was not used before. Must be
     * atomic across every instance that verifies proofs for the same service.
     */
    public function use(string $nonce): bool;
}
