<?php

declare(strict_types=1);

namespace Omniboost\AwsIamProof\Laravel;

use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Omniboost\AwsIamProof\Acl\Acl;
use Omniboost\AwsIamProof\Acl\AclStore;
use Omniboost\AwsIamProof\Exception\InfrastructureException;
use Omniboost\AwsIamProof\Exception\VerificationException;
use Omniboost\AwsIamProof\Principal;
use Omniboost\AwsIamProof\Verifier;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * Verifies the AWS-IAM-PROOF header and, when given permissions, requires
 * every one of them:
 *
 *     Route::get('/orders', ...)->middleware('aws-iam-proof');
 *     Route::post('/orders', ...)->middleware('aws-iam-proof:orders.view,orders.edit');
 *
 * The verified Principal is available as $request->awsIamPrincipal(). Error
 * responses are {"error": message}, the same as the Go middleware.
 */
final class AuthenticateWithAwsIamProof
{
    public function __construct(
        private readonly Verifier $verifier,
        private readonly AclStore $acl,
        private readonly LoggerInterface $logger,
    ) {
    }

    public function handle(Request $request, Closure $next, string ...$permissions): Response
    {
        $authorization = $request->headers->get('Authorization');
        if ($authorization === null || $authorization === '') {
            return self::error(401, 'missing Authorization header');
        }

        try {
            $principal = $this->verifier->verify($authorization);
        } catch (InfrastructureException $e) {
            // A server fault: log at error so it gets reported.
            $this->logger->error('identity verification failed due to infrastructure error', ['exception' => $e]);

            return self::error(401, 'identity verification failed');
        } catch (VerificationException $e) {
            $this->logger->info('identity verification failed', ['error' => $e->getMessage()]);

            return self::error(401, 'identity verification failed');
        }

        $request->attributes->set(Principal::class, $principal);

        foreach ($permissions as $permission) {
            try {
                $allowed = Acl::allows($this->acl, $principal, $permission);
            } catch (Throwable $e) {
                $this->logger->error('permission lookup failed', ['exception' => $e, 'permission' => $permission]);

                return self::error(500, 'authorization lookup failed');
            }
            if (!$allowed) {
                $this->logger->info('permission denied', [
                    'account_id' => $principal->accountId,
                    'role' => $principal->role,
                    'permission' => $permission,
                ]);

                return self::error(403, 'permission denied');
            }
        }

        return $next($request);
    }

    private static function error(int $status, string $message): JsonResponse
    {
        return new JsonResponse(['error' => $message], $status);
    }
}
