# Connect AWS credentials to the broker

Configure one AWS Region and explicit credential references, then run an approved
operation through Opaque:

```sh
export OPAQUE_AWS_REGION=us-east-2
export OPAQUE_AWS_ACCESS_KEY_REF=keychain:opaque/aws-access-key-id
export OPAQUE_AWS_SECRET_KEY_REF=keychain:opaque/aws-secret-access-key
# Set this reference when using temporary STS credentials:
export OPAQUE_AWS_SESSION_TOKEN_REF=keychain:opaque/aws-session-token

# Start the configured broker, then use its ordinary policy and approval flow.
opaque execute aws.get_caller_identity
```

Provision the referenced values in the broker account's custody first. Omit the
session-token reference for long-lived access keys. Each reference must use the
base `keychain:` or `env:` resolver; references must be distinct. This source
implementation requires a release containing the signed AWS client. Older
mock-only AWS builds cannot contact production AWS.

The broker uses AWS's maintained Signature V4 signer with regional STS,
Secrets Manager and SSM endpoints. STS uses Query requests and XML responses;
the other services use their AWS JSON APIs. See the official
[STS protocol](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html),
[Secrets Manager protocol](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html)
and [SSM protocol](https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_GetParameter.html). Commercial, GovCloud and China
regional endpoint suffixes are supported. Credentials and session tokens are
read from the selected references when work executes. No ambient AWS SDK profile,
instance metadata, container credential chain or custom remote endpoint is used.
The selected Region, service endpoint, operation, arguments and credential
references participate in prepared authorization before credentials are read.

## Operations and secret references

The client implements STS caller identity and AssumeRole; Secrets Manager
get/create/put/list/delete; and SSM get/put/list-by-path/delete. IAM permissions
and Opaque policy must both allow the requested operation. The existing reveal
and sensitive-output approval rules still apply. List-by-path returns parameter
metadata through the operation handler, never parameter values.

Use `aws:secret-name` for a Secrets Manager value or
`aws:ssm:/application/parameter` for a decrypted SSM value inside another approved
operation. Secrets Manager binary values are decoded by the resolver. The explicit
`aws.get_secret_value` reveal operation returns binary values as base64 with
`encoding: "base64"`; string responses retain their existing shape. SSM names
may include a supported version or label suffix. These references use the
configured Region; they do not select an alternate endpoint or credential chain.

Collection reads follow service continuation tokens with limits of 100 pages,
10,000 items, 8 MiB of responses and 30 seconds for the whole read. Crossing a
limit fails explicitly instead of reporting an incomplete list as complete.
Individual responses are limited to 2 MiB. Secret writes carry a generated AWS
client request token. Deleting a secret schedules recovery-capable deletion;
the handler never requests force deletion.

Requests do not follow redirects, environment proxies or automatic retries.
A connection failure, lost response or invalid acknowledgment can leave a write's
outcome unknown. Inspect the selected resource independently before authorizing
another write; a failure is not proof that AWS did not apply it. Provider errors
expose fixed classifications and omit upstream response text and credentials.

## Verify the connection

Run the protocol and prepared-action tests without AWS credentials:

```sh
cargo test --locked -p opaque-providers --no-default-features --features aws aws::
```

The fixtures exercise signed requests, actual AWS request/response formats,
session tokens, pagination, binary resolution, redirect rejection and no retry
after a failed write. Fixture mode requires `OPAQUE_AWS_ALLOW_INSECURE=1`, a
literal loopback `OPAQUE_AWS_MOCK_URL`, and the fixed public synthetic values
defined in `aws::client`. It rejects real credentials before sending a request.
It uses the same protocol and signer as production; fixture success does not
establish live AWS account, IAM, KMS or service qualification.

For a separately authorized, read-only acceptance run, configure the references
above and set the expected account explicitly. Optional resource names select
existing test resources that the account owner has approved for reads:

```sh
export OPAQUE_AWS_LIVE_ACCEPTANCE=read-only
export OPAQUE_AWS_LIVE_ACCOUNT=123456789012
# Optional approved test resource selectors:
export OPAQUE_AWS_LIVE_SECRET_NAME=approved-test-secret
export OPAQUE_AWS_LIVE_PARAMETER_NAME=/approved/test/parameter
cargo test --locked -p opaque-providers --no-default-features --features aws \
  aws::client::tests::live_aws_read_only_identity_and_selected_resources -- --ignored --exact
```

This opt-in test checks the actual STS account
before optional reads and prints no fetched secrets. It does not create resources,
assume a new role or run write/delete acceptance. Qualify writes on explicitly
authorized disposable resources through the broker's normal review flow and
retain independent readback before claiming those operations are live-qualified.
