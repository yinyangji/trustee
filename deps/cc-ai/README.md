# Three-party AI job authorization (CPU TDX profile v1)

This implementation adds application-bound asset-owner authorization to Trustee.
It is a control-plane/execution-profile foundation, not a general LLM engine.
GPU, distributed membership, checkpoint rollback protection, output enforcement
and an attested TLS inference server are not implemented by this crate. Contracts
requiring GPU or more than one member fail closed.

See the [asset-owner passport design](../../docs/cc-ai-asset-owner-passport.md)
for the independent model and data KMS flows and their deployment boundaries.

## Trust and topology: passport first

The recommended model/data KMS integration is **Passport**: the workload obtains
an AS result, then presents it to each asset owner. Asset KMS request paths never
call AS, RVPS or vendor collateral services and never interpret native evidence.
`passport::AssetPassportVerifier` implements this boundary with a pinned AS key,
an offline-approved job, per-request holder-of-key proof and one-use challenges.

A reusable stage passport uses separate quote-bound keys: `K_pop` signs resource
redemptions, while `K_enc` receives encrypted keys. AS signs the normalized
`cc-ai.passport.v1` claim and sets `cnf.jwk` to the PoP public key. The result's
private recipient-key field and job digest bind the resource-encryption identity.
Missing PoP claims or legacy EAR tokens are not silently accepted as this profile.

The owner registers the three-party signed contract once with `RegisteredJob`.
For each operation it calls `challenge`, verifies the returned proof through
`redeem`, and only then calls its existing KMS to wrap the exact authorized
resource to the returned recipient key. A valid passport may be reused during
its allowed stage/age; challenges and proofs are always new. No challenge is
consumed before successful proof validation, and concurrent redemption consumes
it only once. The nonce cache is bounded, local and expiring: use shared atomic
storage or appropriate routing when deploying multiple adapter replicas.

The AS-proof acquisition frontend may be the existing platform KBS. This is a
Verifier gateway, not the owner of the business DEKs; the asset-owner RP still
uses Passport. `--passport-pop-public-key` adds a separate public PoP key to the
quote-verified runtime data. The frontend requests an AS-issued challenge
bound to that public key; AS consumes it once after successful appraisal.
Old quote replay cannot mint a fresh reusable passport. Both issuer and RP
challenge caches are currently single-instance; multi-replica deployments need
shared atomic state or reliable session routing.

For compatibility, the older KMS-nonce-in-quote passport path remains available.
It needs fresh proof acquisition per independent KMS challenge and does not offer
stage-token reuse. The previous owner-KBS `cc_ai` background-check resource path
and `RelyingPartyPolicy::authorize` are retained as **legacy**, not the default
passport adapter. Its background session guards are intentionally not relaxed.

The older user-side `verify-passport` CLI validates a legacy service token and
an independently authenticated peer key. It is not a TLS stack. The new reusable
asset passport uses the `passport` module; these two profiles are not interchangeable.
An attested TLS inference server and its transport SDK still require integration.

## Contract and evidence binding

`SignedJob` contains a strict `cc-ai.job.v1` contract and exactly three compact
ES256 JWS signatures over its JCS representation. Pinned authority configuration
maps each key to a role and party ID. Reusing a key or role, changing the payload,
unknown keys, invalid time, revoked job IDs and old policy epochs are rejected.

Put the assembled job JSON in the `cc-ai.job` string inside CoCo InitData **before
computing the launch digest**. The contract pins the exact Agent Policy digest;
AS derives that digest from the actual hash-bound `policy.rego`, overwriting any
user-supplied reserved digest field. The job has no self-referential InitData hash.

AS only derives job results from native-verifier outputs and valid InitData /
ReportData binding. It matches actual RTMR3 against distinct, three-party-approved
stage references:

* `application-ready`: permits an exact model resource grant.
* `model-verified`: may permit an exact data resource grant and an inference
  service passport. This means measured model artifacts under the approved loader
  contract; it does **not** attest GPU residency or arbitrary dynamic execution.

Generate both references offline from approved interpreter, executable/model
snapshots, arguments and expected extension history. Register them in RVPS with
the approved launch digest. Do not enroll a guest-supplied measurement as a
reference. The existing `default` and `application` appraisals must both pass.

The legacy AS job result includes the private claim
`tag:github.com,2026:confidential-containers/cc-ai`, `aud` and normalized `cnf.jwk`.
The claim binds contract digest, job/tenant, stage, nonce, key identity and policy
epoch. Result expiry is capped at 120 seconds and contract expiry. No new field
is asserted to be an upstream EAT/EAR standardized business claim.

For the new passport, AS additionally emits
`tag:github.com,2026:confidential-containers/cc-ai-passport` only when it verifies
a distinct PoP key in native-bound runtime data. The asset adapter consumes that
normalized claim, not InitData or EAR device paths. A permissive KMS resource
policy cannot replace the owner's registered contract or proof validation.

## Configuration

AS: set `attestation_token_broker.cc_ai` to a `TrustPolicy` JSON object:

```json
{
  "authorities": [
    {"key_id":"data-v1","party_id":"data-owner","role":"data","public_key_pem":"<PEM>"},
    {"key_id":"model-v1","party_id":"model-owner","role":"model","public_key_pem":"<PEM>"},
    {"key_id":"user-v1","party_id":"user-owner","role":"user","public_key_pem":"<PEM>"}
  ],
  "minimum_policy_epoch": 1,
  "revoked_jobs": []
}
```

Asset adapter: construct it with a `RelyingPartyPolicy` and pinned AS public key:

```json
{
  "trust": "<replace with the TrustPolicy object above>",
  "issuer": "https://as.example",
  "audience": "https://data-owner.example",
  "role": "data",
  "max_token_age_seconds": 120
}
```

The `trust` placeholder must be an object. Use `role: model` and a distinct
audience for the model owner adapter. Supplying this object as a legacy KBS
top-level `cc_ai` option selects its historical background-check gate, not the
new standalone adapter; there is no automatic migration of an existing KMS. Changes to revoked jobs / minimum epoch currently
require configuration reload by restarting the service. Legacy deployments with
`cc_ai` absent retain their existing behavior; they do not enforce this profile.
Production requires authenticated transport and the trust governance described
in the design. A platform controlling every accepted AS key/policy remains in
the trust base; this crate does not eliminate that governance assumption.

## Offline CLI

```sh
cargo +1.95.0 build -p trustee-cc-ai --locked
cc-ai sign --contract job-contract.json --key-id data-v1 --key data.key --output data.jws
# Each other party independently reviews and signs the same contract.
cc-ai assemble --contract job-contract.json --signatures data.jws model.jws user.jws \
  --trust trust.json --output job.json
cc-ai verify --job job.json --trust trust.json
cc-ai init-data --input initdata.toml --job job.json --trust trust.json --output job-initdata.toml
cc-ai challenge
cc-ai verify-passport --token token.jwt --as-public-key as.pub --policy user-policy.json \
  --nonce USER_CHALLENGE --job-id EXPECTED_JOB --contract-digest EXPECTED_DIGEST \
  --peer-key independently-authenticated-channel-key.json
```

Output files use create-new semantics to prevent accidental approval overwrite.
Key paths, not private key contents, appear in command arguments. Keep key files
under each party's own controls. The CLI does not provision all party keys to a
shared platform; the integration fixture does so only for synthetic testing.

## Reusable passport API

```rust,ignore
use trustee_cc_ai::passport::{AssetPassportVerifier, RegisteredJob};
let approved = RegisteredJob::new(signed_job, &owner_policy.trust, now)?;
let verifier = AssetPassportVerifier::new(owner_policy, pinned_as_public_key)?;
let challenge = verifier.challenge(&approved, &passport_token, resource, now)?;
// The TEE signs the complete challenge using K_pop and sends proof_jws.
let release = verifier.redeem(&approved, &passport_token,
    &challenge.nonce, &proof_jws, now)?;
// Call the owner's existing KMS/HSM only now, using release.resource() and
// release.recipient_key(). Never return a plaintext key to the caller.
```

A trusted TEE proof service can use the provided CLI. Generate keys in a private
TEE tmpfs, not on host mounts; prohibit untrusted programs from reading them:

```sh
cc-ai generate-pop-key --private-key /run/cc-ai/pop.pem --public-key /run/cc-ai/pop.json
# Pass the public JSON into tdx-workload --passport-pop-public-key; keep the
# private key in the approved TEE service. No private key is sent to AS/KMS.
cc-ai proof --challenge kms-challenge.json --key /run/cc-ai/pop.pem --output proof.jws
```

This is a versioned ES256/JWS redemption protocol (`cc-ai-pop+jws`), not a claim
of complete OAuth DPoP support. The proof binds resource, RP audience, contract,
passport digest, timestamp and nonce. Trust configuration changes invalidate
registered approvals. A stolen passport alone cannot sign a valid redemption.

## Verification

```sh
cargo +1.95.0 test -p trustee-cc-ai --locked --offline
cargo +1.95.0 test -p attestation-service --no-default-features \
  --features grpc-bin,tdx-verifier --lib cc_ai_tests --locked --offline
cargo +1.95.0 test -p kbs --no-default-features --features coco-as-grpc --lib --locked --offline
```

Tests cover normalized tokens without raw evidence, independent PoP/recipient
keys, resource scope, repeated and concurrent replay, wrong signatures, expired
challenges and approval changes. AS unit integration uses synthetic native-
verifier outputs plus real signatures; it is not a hardware quote test. The old
CoCo `policy/cc-ai-20261115` background suite is historical and incomplete; it is
not validation of the new reusable passport profile. Real KMS backends, deployed
TLS service identities and hardware end-to-end passport acceptance remain explicit
integration work.
