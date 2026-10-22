<?php

return [

    /*
    | STS region outgoing proofs are signed for. Any region works; the
    | verifier accepts every STS endpoint.
    */
    'region' => env('AWS_IAM_PROOF_REGION', env('AWS_DEFAULT_REGION', 'us-east-1')),

    /*
    | Static credentials for signing, e.g. for local development. Null uses
    | the default AWS credential chain (environment, profile and SSO,
    | container or instance role), which is what production should use.
    */
    'credentials' => env('AWS_IAM_PROOF_ACCESS_KEY_ID') ? [
        'key' => env('AWS_IAM_PROOF_ACCESS_KEY_ID'),
        'secret' => env('AWS_IAM_PROOF_SECRET_ACCESS_KEY'),
        'token' => env('AWS_IAM_PROOF_SESSION_TOKEN'),
    ] : null,

    /*
    | Seconds an outgoing proof stays valid (1 to 120).
    */
    'expires' => 60,

    /*
    | Seconds the verifier waits for STS.
    */
    'sts_timeout' => 10,

    /*
    | Cache store that remembers used nonces, so a captured header cannot be
    | replayed. It must be shared by every instance and support atomic add():
    | redis, memcached, dynamodb or database. Null uses the default store.
    */
    'nonce_store' => env('AWS_IAM_PROOF_NONCE_STORE'),

    'nonce_prefix' => 'aws-iam-proof:nonce:',

    /*
    | Permissions per AWS account and role, as JSON:
    |
    |   [{"account_id": "123456789012", "role": "Developer", "permissions": ["orders.view"]}]
    |
    | An array in the same shape works too. Bind your own
    | Omniboost\AwsIamProof\Acl\AclStore to read grants from elsewhere.
    */
    'acl' => env('AWS_IAM_PROOF_ACL', '[]'),

];
