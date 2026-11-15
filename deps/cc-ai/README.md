# Three-party AI job authorization (CPU TDX profile v1)

This implementation adds application-bound asset-owner authorization to Trustee.
It is a control-plane/execution-profile foundation, not a general LLM engine.
GPU, distributed membership, checkpoint rollback protection, output enforcement
and an attested TLS inference server are not implemented by this crate. Contracts
requiring GPU or more than one member fail closed.

## Trust and topology

Model/data key release uses **background check**: KBS supplies a nonce, forwards
native evidence to AS, consumes the signed result and authorizes its own resource.
Each asset owner configures its own contract authorities and resource policy.
The CPU job profile refuses detached bearer-only resource requests and refuses
client-selected passport nonces at those KBS endpoints.

The user-side **passport** verifier checks a pinned AS P-256 signature, issuer,
audience, age, the user's challenge, expected contract digest/job and connection
public key. `verify-passport` is an offline verification tool, not a TLS stack:
the caller must obtain `peer-key` from a TLS/application connection that has
proved possession of its private key. Never copy the token's `cnf` into that
argument and call it channel verification. The shared library API has the same
precondition.

The separately developed KBS passport gateway may forward proof acquisition to
AS and return the result to a workload. For another RP that then consumes it,
this is a combined RATS topology. It is not enabled as an alternative to the
asset-owner KBS background-check requirement in this profile.

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

The AS result includes the private claim
`tag:github.com,2026:confidential-containers/cc-ai`, `aud` and normalized `cnf.jwk`.
The claim binds contract digest, job/tenant, stage, nonce, key identity and policy
epoch. Result expiry is capped at 120 seconds and contract expiry. No new field
is asserted to be an upstream EAT/EAR standardized business claim.

At resource release, KBS independently checks the role signatures and derives
the same binding from AS-signed evidence, then checks the owner, exact resource,
audience, issuer, time and stage. This runs before any resource backend and in
addition to compiled minimum mode authorization and administrator Rego. A
permissive custom Rego policy cannot bypass it. Configure authenticated admin
access and pinned token roots; insecure embedded header-JWK trust is rejected.

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

KBS: set top-level `cc_ai` to a `RelyingPartyPolicy`:

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
audience for the model KBS. Changes to revoked jobs / minimum epoch currently
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

## Verification

```sh
cargo +1.95.0 test -p trustee-cc-ai --locked --offline
cargo +1.95.0 test -p attestation-service --no-default-features \
  --features grpc-bin,tdx-verifier --lib cc_ai_tests --locked --offline
cargo +1.95.0 test -p kbs --no-default-features --features coco-as-grpc --lib --locked --offline
```

AS unit integration uses synthetic native-verifier output and real AS signatures;
it does not validate a hardware quote. Real CPU TDX acceptance is documented by
the separate CoCo `policy/cc-ai-20261115` harness and its recorded results.
