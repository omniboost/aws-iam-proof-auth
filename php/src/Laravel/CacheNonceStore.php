<?php

declare(strict_types=1);

namespace Omniboost\AwsIamProof\Laravel;

use Illuminate\Contracts\Cache\Repository;
use Omniboost\AwsIamProof\Nonce\NonceStore;
use Omniboost\AwsIamProof\Protocol;

/**
 * Nonce store on a Laravel cache store. It relies on Cache::add(), which is
 * atomic on the redis, memcached, dynamodb and database drivers. The file and
 * array drivers are not shared or not atomic across processes, so they do not
 * stop a replay sent to a second worker.
 */
final class CacheNonceStore implements NonceStore
{
    public function __construct(
        private readonly Repository $cache,
        private readonly string $prefix = 'aws-iam-proof:nonce:',
        private readonly int $ttl = Protocol::NONCE_TTL,
    ) {
    }

    public function use(string $nonce): bool
    {
        return $this->cache->add($this->prefix . $nonce, 1, $this->ttl);
    }
}
