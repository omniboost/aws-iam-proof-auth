<?php

declare(strict_types=1);

namespace Omniboost\AwsIamProof\Tests;

use DateTimeImmutable;
use DateTimeZone;
use Omniboost\AwsIamProof\Verifier;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;

/**
 * Headers signed by the Go and PHP signers must pass the PHP verifier's checks.
 * interop_test.go runs the same fixtures through the Go verifier. They are
 * signed with AWS's documented example key, so only the format is under test.
 */
final class InteropTest extends TestCase
{
    #[TestWith(['go-header.txt'])]
    #[TestWith(['php-header.txt'])]
    public function testFixturePassesValidation(string $fixture): void
    {
        $header = trim((string) file_get_contents(__DIR__ . '/../../testdata/interop/' . $fixture));
        $uri = Verifier::parseAuthorization($header);

        parse_str($uri->getQuery(), $query);
        // Validate as of the signing time, so the fixture never goes stale.
        $signedAt = DateTimeImmutable::createFromFormat('Ymd\THis\Z', $query['X-Amz-Date'], new DateTimeZone('UTC'));

        self::assertNotEmpty(Verifier::validatePresignedUrl($uri, $signedAt->getTimestamp()));
    }
}
