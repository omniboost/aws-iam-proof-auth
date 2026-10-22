<?php

declare(strict_types=1);

namespace Omniboost\AwsIamProof\Nonce;

use Closure;
use Omniboost\AwsIamProof\Protocol;

/**
 * In-process nonce store. Under PHP-FPM every request starts empty, so it only
 * protects against replay within one long-running process (Octane, a queue
 * worker) or in tests. Use CacheNonceStore with a shared cache in production.
 */
final class ArrayNonceStore implements NonceStore
{
    /** @var array<string, int> nonce => expiry timestamp */
    private array $seen = [];

    private readonly Closure $now;

    public function __construct(
        private readonly int $ttl = Protocol::NONCE_TTL,
        ?Closure $now = null,
    ) {
        $this->now = $now ?? static fn (): int => time();
    }

    public function use(string $nonce): bool
    {
        $now = ($this->now)();
        $this->seen = array_filter($this->seen, static fn (int $expiresAt): bool => $expiresAt > $now);

        if (isset($this->seen[$nonce])) {
            return false;
        }
        $this->seen[$nonce] = $now + $this->ttl;

        return true;
    }
}
