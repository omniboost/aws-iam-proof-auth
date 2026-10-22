<?php

declare(strict_types=1);

namespace Omniboost\AwsIamProof\Laravel;

use Aws\Credentials\CredentialProvider;
use Aws\Credentials\Credentials;
use GuzzleHttp\Client;
use GuzzleHttp\RequestOptions;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;
use Omniboost\AwsIamProof\Acl\AclStore;
use Omniboost\AwsIamProof\Acl\ArrayAclStore;
use Omniboost\AwsIamProof\Nonce\NonceStore;
use Omniboost\AwsIamProof\Principal;
use Omniboost\AwsIamProof\Signer;
use Omniboost\AwsIamProof\Verifier;
use Psr\Http\Message\RequestInterface;

/**
 * Registers the signer, verifier, nonce store and ACL store as singletons
 * (bind your own AclStore or NonceStore to replace them), the 'aws-iam-proof'
 * middleware alias, Http::withAwsIamProof() and $request->awsIamPrincipal().
 */
final class AwsIamProofServiceProvider extends ServiceProvider
{
    public const MIDDLEWARE = 'aws-iam-proof';

    private const CONFIG = __DIR__ . '/../../config/aws-iam-proof.php';

    public function register(): void
    {
        $this->mergeConfigFrom(self::CONFIG, 'aws-iam-proof');

        $this->app->singleton(Signer::class, static function (Application $app): Signer {
            $credentials = $app['config']->get('aws-iam-proof.credentials');

            return new Signer(
                is_array($credentials) ? CredentialProvider::fromCredentials(new Credentials(
                    (string) $credentials['key'],
                    (string) $credentials['secret'],
                    ($credentials['token'] ?? null) ?: null,
                )) : null,
                $app['config']->get('aws-iam-proof.region'),
                (int) $app['config']->get('aws-iam-proof.expires'),
            );
        });

        $this->app->singleton(NonceStore::class, static fn (Application $app): NonceStore => new CacheNonceStore(
            $app['cache']->store($app['config']->get('aws-iam-proof.nonce_store')),
            (string) $app['config']->get('aws-iam-proof.nonce_prefix'),
        ));

        $this->app->singleton(AclStore::class, static function (Application $app): AclStore {
            $acl = $app['config']->get('aws-iam-proof.acl') ?? [];

            return is_string($acl) ? ArrayAclStore::fromJson($acl === '' ? '[]' : $acl) : new ArrayAclStore($acl);
        });

        $this->app->singleton(Verifier::class, static fn (Application $app): Verifier => new Verifier(
            $app->make(NonceStore::class),
            new Client([RequestOptions::TIMEOUT => (int) $app['config']->get('aws-iam-proof.sts_timeout')]),
        ));
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([self::CONFIG => $this->app->configPath('aws-iam-proof.php')], 'aws-iam-proof-config');
        }

        $this->callAfterResolving('router', static function (Router $router): void {
            $router->aliasMiddleware(self::MIDDLEWARE, AuthenticateWithAwsIamProof::class);
        });

        $app = $this->app;
        PendingRequest::macro('withAwsIamProof', function () use ($app): PendingRequest {
            /** @var PendingRequest $this */
            return $this->withRequestMiddleware(
                static fn (RequestInterface $request): RequestInterface => $request->withHeader('Authorization', $app->make(Signer::class)->header()),
            );
        });

        Request::macro('awsIamPrincipal', function (): ?Principal {
            /** @var Request $this */
            return $this->attributes->get(Principal::class);
        });
    }
}
