# aws-iam-proof-auth

Service-to-service authentication with the caller's AWS identity. No shared
secrets: a service proves who it is with the IAM role it already runs as.

One repository, two implementations of the same protocol:

- a Go module, `github.com/omniboost/aws-iam-proof-auth`
- a Composer package, `omniboost/aws-iam-proof-auth`, with Laravel integration

A header signed by either one verifies on the other. The tests check this
against shared fixtures in `testdata/`.

## How it works

The caller presigns an STS `GetCallerIdentity` request with its own AWS
credentials and sends the presigned URL in the `Authorization` header:

```
Authorization: AWS-IAM-PROOF <base64url(presigned STS URL)>
```

The receiving service:

1. checks the URL is an https STS endpoint (`sts.*.amazonaws.com`,
   `sts-fips.*`, `sts.*.api.aws`) calling `GetCallerIdentity`;
2. checks `X-Amz-Expires` is at most 120 seconds and `X-Amz-Date` is at most
   5 minutes old;
3. claims the `X-Amz-Nonce` in a shared nonce store, so the header works once;
4. calls the URL. STS answers with the caller's ARN, for example
   `arn:aws:sts::123456789012:assumed-role/Developer/alice`.

The result is a principal: account ID `123456789012`, role `Developer`. SSO
roles lose their generated parts, so `AWSReservedSSO_Developer_0a1b2c3d` becomes
`Developer`. Only assumed roles are accepted. IAM users are rejected.

The nonce is in the query before signing, so the signature covers it. The
receiver never sees the caller's credentials, only a URL that STS accepts once
within a minute. That is also why the code can be public: everything it does is
standard AWS signing and a call to STS.

Permissions are granted per account ID + role. They are plain strings such as
`pipelines.view` and mean whatever the receiving service decides.

## ACL grants

Both languages read the same JSON, from the `AWS_IAM_PROOF_ACL` environment
variable or from wherever you pass it in:

```json
[
  {"account_id": "123456789012", "role": "Developer", "permissions": ["pipelines.view", "pipelines.edit"]},
  {"account_id": "210987654321", "role": "ci-deploy", "permissions": ["pipelines.view"]}
]
```

Parsing is strict, because a typo silently denies access: unknown fields, an
account ID that is not 12 digits, an empty role or an empty permission are
errors. Entries for the same account + role are merged. The Go Mongo store
reads documents of the same shape.

## Go

```sh
go get github.com/omniboost/aws-iam-proof-auth
```

### Signing outgoing requests

```go
import iamproof "github.com/omniboost/aws-iam-proof-auth"

signer, err := iamproof.NewDefaultSigner(ctx) // or iamproof.NewSigner(awsConfig)
if err != nil {
	return err
}

// Every request gets a fresh header, retries included.
client := &http.Client{Transport: &iamproof.Transport{Signer: signer}}

// Or by hand:
header, err := signer.Header(ctx)
req.Header.Set("Authorization", header)
```

Build the signer once. It keeps the `aws.Config`, so credentials are cached
instead of reloaded per request.

### Verifying incoming requests

```go
import (
	iamproof "github.com/omniboost/aws-iam-proof-auth"
	"github.com/omniboost/aws-iam-proof-auth/acl"
	"github.com/omniboost/aws-iam-proof-auth/middleware"
	"github.com/omniboost/aws-iam-proof-auth/valkeynonce"
)

verifier := iamproof.NewVerifier(valkeynonce.New(valkeyClient))

store, ok, err := acl.FromEnv() // AWS_IAM_PROOF_ACL
if err != nil {
	return err
}
if !ok {
	store = acl.NewMemoryStore() // no grants: every permission check fails
}

auth := middleware.NewAuth(verifier, store, middleware.WithLogger(logger))

mux.Handle("GET /pipelines", auth.Require("pipelines.view")(listHandler))
mux.Handle("POST /identity", auth.Require()(identityHandler)) // identity only

// In a handler:
principal, _ := iamproof.PrincipalFromContext(r.Context())
```

Errors are JSON, `{"error": "..."}`: 401 for a missing or invalid proof, 403 for
a missing permission, 500 when the ACL lookup fails. Use
`middleware.WithErrorWriter` to change the format. When the nonce store or STS
fails, the error wraps `iamproof.ErrInfrastructure` and is logged at error level.
An invalid proof is logged at info.

Packages:

| Package       | What                                                                              |
|---------------|-----------------------------------------------------------------------------------|
| `iamproof`    | `Signer`, `Transport`, `Verifier`, `Principal`, `MemoryNonceStore`                |
| `acl`         | `Store`, `MemoryStore`, `CachedStore` (5s TTL), `ParseGrants`, `FromEnv`          |
| `acl/mongoacl`| `Store` on a Mongo collection (`acl_grants`), with `EnsureIndexes`                |
| `valkeynonce` | Nonce store on Valkey/Redis (`SET NX EX`), shared across instances                |
| `middleware`  | net/http middleware: `RequireIdentity`, `RequirePermission`, `Auth.Require`       |

`MemoryNonceStore` only protects a single process. Anything with more than one
instance, Lambda included, needs `valkeynonce` or another shared store.

### Postman

Postman cannot run AWS signing in a pre-request script, so a loopback helper
makes the header for it:

```sh
go run github.com/omniboost/aws-iam-proof-auth/cmd/authhelper@latest          # http://127.0.0.1:7070
go run github.com/omniboost/aws-iam-proof-auth/cmd/authhelper@latest -print   # print one header
```

`GET /` returns `{"authorization": "AWS-IAM-PROOF ..."}`. Set it as the
`Authorization` header in a pre-request script.

## PHP / Laravel

```sh
composer require omniboost/aws-iam-proof-auth
```

Requires PHP 8.2+. The Laravel integration supports Laravel 12 and 13 and is
auto-discovered.

### Signing outgoing requests

```php
// Laravel: a fresh header per request, retries included.
Http::withAwsIamProof()->get('https://api.example.com/v1/identity');

// Plain Guzzle:
$stack = HandlerStack::create();
$stack->push(GuzzleMiddleware::sign(new Signer()));
$client = new Client(['handler' => $stack]);

// By hand:
$header = (new Signer())->header();
```

`Signer` uses the AWS SDK's default credential chain unless you pass a
credential provider. In Laravel, set `AWS_IAM_PROOF_ACCESS_KEY_ID` and
`AWS_IAM_PROOF_SECRET_ACCESS_KEY` to sign with static keys, for example in local
development.

### Verifying incoming requests

```php
Route::get('/orders', ...)->middleware('aws-iam-proof');                            // identity only
Route::post('/orders', ...)->middleware('aws-iam-proof:orders.view,orders.edit');   // and every listed permission

// In the controller:
$principal = $request->awsIamPrincipal(); // Omniboost\AwsIamProof\Principal
$principal->accountId;
$principal->role;
```

Responses and status codes match the Go middleware.

Used nonces go into a Laravel cache store, through `Cache::add()`. That store
must be shared by every instance and atomic: redis, memcached, dynamodb or
database. The file and array drivers do not stop a replay sent to another
worker. Pick the store with `AWS_IAM_PROOF_NONCE_STORE`.

Grants come from `AWS_IAM_PROOF_ACL`. To read them from somewhere else, bind
your own `Omniboost\AwsIamProof\Acl\AclStore` in a service provider.

To change the defaults, publish the config:

```sh
php artisan vendor:publish --tag=aws-iam-proof-config
```

| Env                                  | Default                              |
|--------------------------------------|--------------------------------------|
| `AWS_IAM_PROOF_REGION`               | `AWS_DEFAULT_REGION`, then us-east-1 |
| `AWS_IAM_PROOF_ACCESS_KEY_ID` / `_SECRET_ACCESS_KEY` / `_SESSION_TOKEN` | unset: default chain |
| `AWS_IAM_PROOF_NONCE_STORE`          | default cache store                  |
| `AWS_IAM_PROOF_ACL`                  | `[]`: no grants                      |

Outside Laravel, use `Verifier` with any `NonceStore` and `ArrayAclStore`
directly. It throws `InvalidProofException` for client errors and
`InfrastructureException` for failures on the verifying side.

## Development

```sh
go test ./...                    # Go
composer install && composer test  # PHP (installs into php/vendor)
```

Composer installs into `php/vendor`. A `vendor/` in the repository root would
put the Go toolchain into vendor mode.

With a live AWS session (e.g. after `aws sso login`) the Go signer tests sign
with it. Without one they use throwaway keys, since signing never leaves the
process.

`testdata/proof/urls.json` and `testdata/acl/*.json` hold the validation cases
both languages run, and `testdata/interop/` holds a header signed by each. If
you change a rule, change it in both implementations; the shared tests fail
until you do.

## Releasing

Tag `vX.Y.Z` on master. The same tag serves Go modules and Composer.
