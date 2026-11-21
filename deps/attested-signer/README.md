# Attested AS signer (TDX, opt-in)

This profile lets a client authenticate the platform AS's runtime and ephemeral
signing key before accepting an application passport. It follows the same trust
construction as an attested signing service; it does **not** implement Azure's
wire protocol or an OIDC identity provider.

The existing deployment path is unchanged: request `default` to evaluate
`default_cpu` and release image keys. For inference sessions, request `default`
and `application` together (KBS mode `workload`), evaluating `default_cpu` and
`application_cpu`. A deployment-only passport cannot satisfy the application
verifier in this crate.

## Trust chain

1. The customer installs an approved `SignerTrustPolicy` through their trusted
   product publisher, enterprise policy distribution, or audit acceptance
   process. A download from the AS being verified is not an endorsement.
2. The client generates a fresh, single-use AS nonce. The AS generates a native
   TDX Quote binding that nonce to its **actual** P-256 signing public key,
   release manifest digest, issuer, and the digest of its appraisal inputs.
3. The client validates the Quote with Intel DCAP, rejects debug/expired
   collateral/unapproved TCB states, and compares the full correlated AS release
   tuple against its local policy. RTMR3 and MRCONFIGID must be nonzero and
   explicitly approved. A manifest digest asserted by the AS is insufficient.
4. Only this path constructs `VerifiedSigner`. It verifies the application's
   ES256 passport, issuer, lifetime, per-policy statuses and exact hashes,
   governance digest, and quote-bound audience/nonce/session/recipient key.
   Only success constructs `VerifiedApplicationPassport`.
5. The client encrypts its DEK to that verified inference recipient or uses the
   recipient bound to its secure session. With BYOK, it first unwraps the DEK
   through its own KMS after verification. KEKs and KMS credentials stay with
   the customer. This crate does not call a KMS or send inference data.

The AS evidence binding is `SHA512(JCS(Binding))` in all 64 REPORTDATA bytes.
`kid`, `instance_id`, and `signing_spki_sha256` are lowercase
`SHA256(DER-SPKI(pk-AS))`. Signing keys never come from an evidence request.
The native verifier always selects TDX; there is no sample/proof-bypass option.

## AS configuration and endpoints

Build the protected AS with one or both frontends:

```sh
cargo build -p attestation-service --no-default-features \
  --features grpc-bin,restful-bin,tdx-verifier,tdx-self-attestation
```

The TDX self-attester and verifier are independent features. A deployment needs
both when this AS also verifies TDX inference workloads. Intel DCAP development
headers/runtime, OpenSSL, and `protoc` are build dependencies.

Start from [as.json.template](examples/as.json.template). Replace every placeholder
using an approved release and workload reference snapshot; templates intentionally
fail validation. `signer` and the legacy `cc_ai` job profile must be absent.
The token lifetime must be 1–5 minutes. Signing keys are generated in memory
once per AS instance and are never loaded or sealed to a file in this mode.
Temporary PEM material used by the EAR signing library is zeroized.

`self_attestation.governance` contains:

- `policy_hashes`: actual policy IDs (including `_cpu`) to SHA-384 of the exact
  Rego source bytes. For built-ins use the files under
  `attestation-service/src/ear_token/`; `sha384sum` gives these hashes.
- `reference_values`: an immutable RVPS-compatible map of reference IDs to
  nonempty arrays. These are the **actual** inputs returned to the policy
  extension. The application policy uses `application_rtmr_3` and
  `application_init_data`, alongside the default CPU's boot reference values.
- `expires_at`: Unix seconds, bounding the entire snapshot and every token
  produced with it.

The AS checks the evaluated policy's actual hash before signing. Missing
references, policy errors, unapproved policy hashes, non-affirming results,
expired snapshots, empty evidence, and sample evidence cannot get a token in
this mode. External RVPS changes cannot override the approved snapshot. Legacy
mode keeps its existing behavior, including signed negative EAR results.

Both REST AS and gRPC AS expose these HTTP endpoints, relative to the configured
fixed HTTPS issuer (a reverse proxy may supply TLS):

| Endpoint | Purpose |
| --- | --- |
| `GET /.well-known/attestation-configuration` | Fixed issuer, metadata URLs, binding profile, signing algorithm |
| `GET /.well-known/jwks.json` | Instance public key and stable `kid`; discovery alone provides no trust |
| `POST /signer-evidence` | Body `{"kid":"<64 hex>","nonce":"<64 hex>"}`; native Quote for this key only |

The proof request is limited to 1 KiB, Quote work to one concurrent request per
instance and a 30-second asynchronous deadline, and proof responses use
`Cache-Control: no-store`. Unsupported builds fail startup if configured for
self-attestation. Missing TDX hardware cannot produce a successful proof.
With multiple replicas, route proof requests to the instance identified by
`kid`; an unknown key fails closed. No raw signing endpoint is exposed.

## Client configuration and tools

Build with the native client verifier:

```sh
cargo build -p trustee-attested-signer --features cli
as-governance-digest --config as.json
verify-as-passport --trust signer-trust.json --session session.json --token passport.jwt
```

`as-governance-digest` computes SHA-256 of the canonical **actual** governance
object. Approve its contents and distribute the resulting digest independently;
computing a hash does not make its inputs trustworthy. The client does not follow
URLs from JWT headers or redirects, and only requests evidence from the fixed
HTTPS issuer in the local trust policy. Evidence responses are limited to 1 MiB.

Use [signer-trust.json.template](examples/signer-trust.json.template) for the
customer's approved AS release tuples, governance digest allowlist, current
revocations, expiry, and explicit TCB status allowlist. `UpToDate` is recommended.
The existing workload policy's temporary `OutOfDate` allowance does not relax
this independent AS trust policy. Each release entry is one complete tuple;
measurements from different entries cannot be combined.

Use [session.json.template](examples/session.json.template) for locally generated
32-byte random nonce and session ID, the actual inference recipient P-256 public
key, audience, and **both** expected policy hashes. These identifiers must be
sent as structured, Quote-bound workload runtime data:

SDK integrations can use `SessionExpectation::new` to generate independent
cryptographic nonce/session IDs, and `auth_extra_params()` to construct the
CoCo `workload` handshake parameters.

```json
{
  "audience": "customer-inference",
  "nonce": "<client-generated-32-byte-lowercase-hex>",
  "session_id": "<client-generated-32-byte-lowercase-hex>",
  "tee-pubkey": {"kty":"EC","crv":"P-256","alg":"ECDH-ES+A256KW","x":"<base64url>","y":"<base64url>"}
}
```

For the existing CoCo KBS handshake, send `passport-audience`, `passport-nonce`,
and `passport-session-id` in the auth request's `extra-params`. KBS reconstructs
these fields from the stored auth session when verifying the primary Quote;
changing them afterwards breaks REPORTDATA verification. The TDX measurement
tool supports the same fields:

```sh
tdx-workload --url "$KBS_URL" --selector workload \
  --passport-audience customer-inference --passport-nonce "$CLIENT_NONCE" \
  --passport-session-id "$CLIENT_SESSION_ID" --init-data init-data.toml \
  --file /approved/inference-service --output-dir /run/inference-passport
```

Run the AS as a standalone service and configure KBS1 to use its gRPC API. The
client fetches the AS proof directly from the fixed issuer. KBS's existing
static-key RP helper does not automatically perform this bootstrap; customer
SDKs or KBS2 integrations must use `VerifiedSigner` for this attested profile.
The measurement tool demonstrates the attestation transcript; the command above
does not launch a long-running inference service or retain its recipient key
after the tool exits. A production inference endpoint must retain its own
session key inside the approved domain and serve the bound inference session.

The EAR profile checks audience in this authenticated runtime data, rather than
requiring a top-level OIDC `aud`. An existing top-level audience cannot replace
the runtime binding. The inference service must own the recipient private key
inside its approved domain; merely inserting a public key into runtime data
does not establish such ownership. The approved application protocol and launch
policy must enforce that rule. The client must encrypt to the returned verified
recipient (or authenticate possession of it in its session), enforce single-use
session challenges, and perform its own resource authorization. The CLI verifies
an existing session transcript; it does not generate an inference session or
maintain a persistent session replay database.

`SignerChallenge` expires after 60 seconds and is consumed by native verification
even on failure. `VerifiedSigner` expires after at most five minutes, and cannot
outlive its local trust policy. Refresh it after policy/revocation updates;
existing cached handles have a maximum five-minute revocation window. Tokens
must have a positive lifetime of at most five minutes, no future issuance time,
and must not be expired. Keep client/guest clocks synchronized.

## Deployment boundary and current scope

TDX protects the AS guest from its host. It does not protect an AS key from
another root process **inside the same guest**. Before endorsing release tuples,
review and enforce an immutable guest/rootfs, restrictive measured Init-Data and
Agent Policy, dependency closure, no debug/SSH/exec/arbitrary process execution,
no writable code mounts, disabled swap/core dumps, and approved migration/snapshot behavior. A shared
development guest is not an acceptable release. These properties are deployment
acceptance requirements, not inferred from a nonzero measurement or claimed by
the proof endpoint. This is an in-memory TEE signer, not an HSM key handle.

This implementation uses one immutable governance snapshot per AS instance.
Online policy modification is disabled in this mode. The low-level broker
`issue(TeeClaims, ...)` API is now crate-private so external callers must use
`AttestationService::evaluate` and native evidence verification. Publishing a new snapshot
currently means starting a new instance and approving its governance digest;
signed hot updates, tenant-scoped snapshot catalogs and transparency receipts
are not implemented here. AS release identity and governance digest remain
separate fields; a reference-only change does not require a new approved AS
code measurement. The protected image must include that separation in its
launch policy instead of measuring mutable tenant references as executable code.

The native proof path is implemented. Unit tests use explicitly synthetic
native-verifier outputs to test appraisal and signing invariants, and reject a
fabricated Quote through the real DCAP path. HTTP integration tests start both
frontends and reject key injection, invalid challenges and oversized requests.
A successful real-Quote round trip still requires an approved TDX AS guest and
a separately approved inference workload; local unit success does not claim
that deployment acceptance has been completed.

Run each component with the appropriate features (avoid workspace-wide hardware
feature unification when checking a TDX-only deployment):

```sh
cargo test -p attestation-service --no-default-features \
  --features grpc-bin,restful-bin,tdx-verifier,tdx-self-attestation
cargo test -p trustee-attested-signer --features cli
cargo test -p kbs --no-default-features --features coco-as-grpc passport::
cargo test -p tdx-workload
cargo fmt --all -- --check
```

Run `cargo clippy --all-targets -- -D warnings` with the same package/feature
selection for each changed component. HTTP integration tests need loopback
listening permission; the launcher regression test needs permission to execute
sealed file descriptors and drop privileges.
