<?php

declare(strict_types=1);

namespace Omniboost\AwsIamProof\Tests\Laravel;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Illuminate\Http\Client\Request as HttpRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Omniboost\AwsIamProof\Acl\AclStore;
use Omniboost\AwsIamProof\Laravel\AwsIamProofServiceProvider;
use Omniboost\AwsIamProof\Laravel\CacheNonceStore;
use Omniboost\AwsIamProof\Nonce\NonceStore;
use Omniboost\AwsIamProof\Signer;
use Omniboost\AwsIamProof\Tests\SignerTest;
use Omniboost\AwsIamProof\Tests\VerifierTest;
use Omniboost\AwsIamProof\Verifier;
use Orchestra\Testbench\TestCase;
use RuntimeException;

final class LaravelTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [AwsIamProofServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('aws-iam-proof.acl', json_encode([
            ['account_id' => '123456789012', 'role' => 'MyRole', 'permissions' => ['orders.view']],
        ]));
    }

    protected function defineRoutes($router): void
    {
        Route::get('/identity', static fn (Request $request) => response()->json($request->awsIamPrincipal()))
            ->middleware('aws-iam-proof');
        Route::get('/orders', static fn () => 'orders')->middleware('aws-iam-proof:orders.view');
        Route::post('/orders', static fn () => 'created')->middleware('aws-iam-proof:orders.view,orders.edit');
    }

    /**
     * Swaps the verifier's STS client for one answering from $responses.
     *
     * @param list<Response> $responses
     */
    private function fakeSts(array $responses): void
    {
        $this->app->instance(Verifier::class, new Verifier(
            $this->app->make(NonceStore::class),
            new Client(['handler' => HandlerStack::create(new MockHandler($responses))]),
        ));
    }

    public function testMissingHeader(): void
    {
        $this->getJson('/identity')->assertStatus(401)->assertExactJson(['error' => 'missing Authorization header']);
    }

    public function testVerifiedPrincipalReachesTheRoute(): void
    {
        $this->fakeSts([new Response(200, [], VerifierTest::identityXml())]);

        $this->getJson('/identity', ['Authorization' => VerifierTest::header('n-1')])
            ->assertOk()
            ->assertExactJson([
                'account_id' => '123456789012',
                'role' => 'MyRole',
                'session' => 'my-session',
                'arn' => VerifierTest::ARN,
            ]);
    }

    public function testReplayIsRejectedThroughTheCache(): void
    {
        $this->fakeSts([new Response(200, [], VerifierTest::identityXml()), new Response(200, [], VerifierTest::identityXml())]);
        $header = VerifierTest::header('once');

        $this->getJson('/identity', ['Authorization' => $header])->assertOk();
        $this->getJson('/identity', ['Authorization' => $header])->assertStatus(401);
        self::assertTrue(Cache::has('aws-iam-proof:nonce:once'));
    }

    public function testStsFailureIs401(): void
    {
        $this->fakeSts([new Response(403, [], 'AccessDenied')]);

        $this->getJson('/identity', ['Authorization' => VerifierTest::header('n')])
            ->assertStatus(401)
            ->assertExactJson(['error' => 'identity verification failed']);
    }

    public function testPermissionGranted(): void
    {
        $this->fakeSts([new Response(200, [], VerifierTest::identityXml())]);

        $this->get('/orders', ['Authorization' => VerifierTest::header('n')])->assertOk()->assertSee('orders');
    }

    public function testEveryPermissionIsRequired(): void
    {
        $this->fakeSts([new Response(200, [], VerifierTest::identityXml())]);

        $this->postJson('/orders', [], ['Authorization' => VerifierTest::header('n')])
            ->assertStatus(403)
            ->assertExactJson(['error' => 'permission denied']);
    }

    public function testAclLookupFailureIs500(): void
    {
        $this->fakeSts([new Response(200, [], VerifierTest::identityXml())]);
        $this->app->instance(AclStore::class, new class implements AclStore {
            public function permissions(string $accountId, string $role): array
            {
                throw new RuntimeException('db down');
            }
        });

        $this->getJson('/orders', ['Authorization' => VerifierTest::header('n')])->assertStatus(500);
    }

    public function testBindings(): void
    {
        self::assertInstanceOf(CacheNonceStore::class, $this->app->make(NonceStore::class));
        self::assertSame($this->app->make(Signer::class), $this->app->make(Signer::class));
        self::assertSame(['orders.view'], $this->app->make(AclStore::class)->permissions('123456789012', 'MyRole'));
    }

    public function testStaticCredentialsFromConfig(): void
    {
        $this->app['config']->set('aws-iam-proof.credentials', ['key' => 'AKIAIOSFODNN7EXAMPLE', 'secret' => 'secret']);
        $this->app['config']->set('aws-iam-proof.region', 'eu-central-1');
        $this->app->forgetInstance(Signer::class);

        $url = $this->app->make(Signer::class)->presignedUrl();

        self::assertStringStartsWith('https://sts.eu-central-1.amazonaws.com/', $url);
        self::assertStringContainsString('X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F', $url);
    }

    public function testHttpMacroSignsEveryRequest(): void
    {
        $this->app->instance(Signer::class, SignerTest::signer());
        Http::fake();

        Http::withAwsIamProof()->get('https://api.example.test/a');
        Http::withAwsIamProof()->get('https://api.example.test/b');

        $headers = [];
        Http::assertSent(static function (HttpRequest $request) use (&$headers): bool {
            $headers[] = $request->header('Authorization')[0] ?? '';

            return true;
        });
        self::assertCount(2, $headers);
        self::assertStringStartsWith('AWS-IAM-PROOF ', $headers[0]);
        self::assertNotSame($headers[0], $headers[1]);
    }
}
