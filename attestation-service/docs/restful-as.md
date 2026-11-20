# Restful Attestation Service

`restful-as` is an Attestation Service application based on RESTful.

Now the following types of evidence are supported:
- `az-snp-vtpm`: Azure SNP vTPM
- `sev`: AMD SEV (Not implemented)
- `sgx`: Intel SGX
- `snp`: AMD SNP
- `tdx`: Intel TDX
- `cca`: Arm CCA
- `sample`: A fake platform. Only for test and sample
- `csv`: Hygon CSV
- `az-tdx-vtpm`: Azure TDX vTPM
- `se`: IBM Secure Execution

## Quick Start

Users can use a [community version of restful CoCoAS image](https://github.com/confidential-containers/trustee/pkgs/container/staged-images%2Fcoco-as-restful) to verify attestation reports.

```shell
# run restful CoCoAS server locally
docker run -d \
  -p 8080:8080 \
  ghcr.io/confidential-containers/staged-images/coco-as-restful:latest
```

Then an attestation request can be used to request the server. We provide an [example request of validating a SGX quote](../tests/coco-as/request.json).

You can use the [tool](https://github.com/confidential-containers/guest-components/tree/main/attestation-agent/attester#evidence-getter-tool) to generate a report on
any supported platform.

```shell
cd <path-to-attestation-service>
curl -k -X POST http://127.0.0.1:8080/attestation \
     -i \
     -H 'Content-Type: application/json' \
     -d @tests/coco-as/request.json
```

Then, a token will be retrieved as HTTP response body like
```plaintext
eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJjdXN0b21pemVkX2NsYWltcyI6eyJ0ZXN0X2tleSI6InRlc3RfdmFsdWUifSwiZXZhbHVhdGlvbi1yZXBvcnRzIjpbeyJldmFsdWF0aW9uLXJlc3VsdCI6IntcImFsbG93XCI6dHJ1ZX0iLCJwb2xpY3ktaGFzaCI6ImMwZTc5Mjk2NzFmYjY3ODAzODdmNTQ3NjBkODRkNjVkMmNlOTYwOTNkZmIzM2VmZGEyMWY1ZWIwNWFmY2RhNzdiYmE0NDRjMDJjZDE3N2IyM2E1ZDM1MDcxNjcyNjE1NyIsInBvbGljeS1pZCI6ImRlZmF1bHQifV0sImV4cCI6MTcwMTY3Mjk2NSwiaXNzIjoiQ29Dby1BdHRlc3RhdGlvbi1TZXJ2aWNlIiwiandrIjp7ImFsZyI6IlJTMzg0IiwiZSI6IkFRQUIiLCJrdHkiOiJSU0EiLCJuIjoiMGhGUHdHNmdTSmJKV1NaTFR6SzRfVThHSWo5WVdYc3FZbDFjbUhveHlhQ05oQ3JCYVVUcW5KdHlPRVpMLVBDcWJBS2VXNGFCWnY1M3Zycm13OU41S2lHMHNOTVJOMUc1V2V2RTFNSEEzQU1qNlNlSWtwT1hzT01DNzJBNUZrZFIzRG1hM3dMaW5tZUVHYk9xZE5rN2IzMHdtWkRhVG13QTJJSjdnNVhPZk8zNTl6YWFLaDFRZDdPUXRkT2RfaV8tQlEzQlpEYnZ4R1ctWmRsdHVwWXBjRVQwWUZLSlE1NTdPSGtsOGMxT3BVdFc5ODlEQjM3d1BGTlRxM25oU3ZveDBwYWdDd3FwZ3JCYXVVUDBlOGlkX1VhSGFVZWlPd2tXc2UxdkdYQW55cFZqUlhhdERhS2dzbzZ5QjdGQ3pMUmRwM3JzWW1kd1lMaTdtMms3TkNPaE9RIn0sIm5iZiI6MTcwMTY3MjY2NSwidGNiLXN0YXR1cyI6eyJzZ3guYm9keS5hdHRyaWJ1dGVzLmZsYWdzIjoiMDcwMDAwMDAwMDAwMDAwMCIsInNneC5ib2R5LmF0dHJpYnV0ZXMueGZybSI6ImU3MDAwMDAwMDAwMDAwMDAiLCJzZ3guYm9keS5jb25maWdfaWQiOiIwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsInNneC5ib2R5LmNvbmZpZ19zdm4iOiIwMDAwIiwic2d4LmJvZHkuY3B1X3N2biI6IjA2MDYwYzBjZmZmZjAwMDAwMDAwMDAwMDAwMDAwMDAwIiwic2d4LmJvZHkuaXN2X2V4dF9wcm9kX2lkIjoiMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJzZ3guYm9keS5pc3ZfZmFtaWx5X2lkIjoiMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJzZ3guYm9keS5pc3ZfcHJvZF9pZCI6IjAwMDAiLCJzZ3guYm9keS5pc3Zfc3ZuIjoiMDAwMCIsInNneC5ib2R5Lm1pc2Nfc2VsZWN0IjoiMDEwMDAwMDAiLCJzZ3guYm9keS5tcl9lbmNsYXZlIjoiOGYxNzNlNDYxM2ZmMDVjNTJhYWYwNDE2MmQyMzRlZGFlOGM5OTc3ZWFlNDdlYjIyOTlhZTE2YTU1MzAxMWM2OCIsInNneC5ib2R5Lm1yX3NpZ25lciI6IjgzZDcxOWU3N2RlYWNhMTQ3MGY2YmFmNjJhNGQ3NzQzMDNjODk5ZGI2OTAyMGY5YzcwZWUxZGZjMDhjN2NlOWUiLCJzZ3guYm9keS5yZXBvcnRfZGF0YSI6Ijc0NjU3Mzc0MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwic2d4LmJvZHkucmVzZXJ2ZWQxIjoiMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwic2d4LmJvZHkucmVzZXJ2ZWQyIjoiMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsInNneC5ib2R5LnJlc2VydmVkMyI6IjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJzZ3guYm9keS5yZXNlcnZlZDQiOiIwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJzZ3guaGVhZGVyLmF0dF9rZXlfZGF0YV8wIjoiMDAwMDAwMDAiLCJzZ3guaGVhZGVyLmF0dF9rZXlfdHlwZSI6IjAyMDAiLCJzZ3guaGVhZGVyLnBjZV9zdm4iOiIwZDAwIiwic2d4LmhlYWRlci5xZV9zdm4iOiIwODAwIiwic2d4LmhlYWRlci51c2VyX2RhdGEiOiJkY2NkZTliMzFjZTg4NjA1NDgxNzNiYjRhMmE1N2ExNjAwMDAwMDAwIiwic2d4LmhlYWRlci52ZW5kb3JfaWQiOiI5MzlhNzIzM2Y3OWM0Y2E5OTQwYTBkYjM5NTdmMDYwNyIsInNneC5oZWFkZXIudmVyc2lvbiI6IjAzMDAifX0.SG7TUxm0E3yZs7rozijScMJIZTY8WVPZN3Yxu2CsW8HFE6lDLymdTzc1XTVrYb97PpGc6oCLwuLax786XHLN250SY_IW5GmR5WKRcYSGSQtOnYfsY7AMX3hvpV3rHGjP0QWZo_ezUp9yIbnJNwSprmFTzcNZkr2YNr1KmwWU-LhGSVCyviQwgtnqnhmQGwH-nHCcmgk0F3su_hdoFXImCggSHStXECAJ0cNjpAuTCsSQvrB4g3lM-dMii-D6a58uB_TGuOVf8Yqj9Gi6PrdxvIJZc1LSDDgo9uYuavNzunU3S3TkA2ZLDK4HIB0zDWfOnS2ZTrjyRdu5ZkzoGVK_YQ
```

The value is a base64 encoded JWT. The body of the JWT is showed in the [example.token.json](./example.token.json).


More configuration items please refer to the [document](./config.md).

## Advanced Topics

### Building from Source

For advanced developers, a restful CoCoAS can be built from source code. Here are the steps.

#### Binary Build and Run

Build and install binary
```shell
git clone https://github.com/confidential-containers/trustee
cd trustee/attestation-service
WORKDIR=$(pwd)
make VERIFIER=all-verifier && make install

# You can use different verifier by changing the value of VERIFIER
```

- For help information, run:
```shell
restful-as --help
```

- For version information, run:
```shell
restful-as --version
```

Start Attestation Service and specify the listen port of its web service:
```shell
restful-as --socket 127.0.0.1:8080
```

If you want to see the runtime log, run:
```shell
RUST_LOG=debug restful-as --socket 127.0.0.1:8080 -c config.json
```

#### Image Build

Build and run container image
```shell
git clone https://github.com/confidential-containers/trustee
cd trustee
docker build \
  -t coco-as:restful \
  -f attestation-service/docker/as-restful/Dockerfile \
  --build-arg VERIFIER=all-verifier \
  .
```

Or you can run the binary in a podman container:
```shell
# Build the restful-as container image
podman build \
    -t restful-as \
    -f attestation-service/docker/as-restful/Dockerfile \
    .

# Run the restful-as container
podman run \
    -d \
    -p 50004:50004 \
    --net host \
    restful-as
```

### HTTPS support

Generate self-signed cert (Optional)

```shell
# Generate a RSA private key
openssl genrsa -out private_key.key 2048

# Generate the public key cert
openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout private_key.key -out certificate.crt
```

Launch the HTTPS CoCo-AS Server
```shell
RUST_LOG=debug restful-as \
    --socket 127.0.0.1:8080 \
    -c config.json \
    --https-pubkey-cert certificate.crt \
    --https-prikey private_key.key
```

### API

RESTful CoCo-AS's endpoints are as following:
- `/attestation`: receives evidence verification request. The request POST payload is like
```json
{
    "verification_requests": [ // each JSON object is a single attestation request. All requests will be processed
                               // alltogether with the given policies.
        {
            "tee": "sgx", // tee type.
            "evidence": "YWFhCg==...", // base64 encoded evidence in URL SAFE NO PAD,
            "runtime_data": {           // `runtime_data` is optional. If given, the runtime data binding will
                                        // be checked.
                                        // The field `raw` and `structured` are exclusive.
                "raw": "YWFhCg==...",   // Base64 encoded runtime data slice. The whole string will be base64
                                        // decoded. The result one will then be accumulated into a digest which
                                        // is used as the expected runtime data to check against the one inside
                                        // evidence.
                                        //
                                        // The alphabet is URL_SAFE_NO_PAD.
                                        // defined in https://datatracker.ietf.org/doc/html/rfc4648#section-5
                                        
                "structured": {}        // Runtime data in a JSON map. CoCoAS will rearrange each layer of the
                                        // data JSON object in dictionary order by key, then serialize and output
                                        // it into a compact string, and perform hash calculation on the whole
                                        // to check against the one inside evidence. The hash algorithm is defined
                                        // by `runtime_data_hash_algorithm`.
                                        //
                                        // After the verification, the structured runtime data field will be included
                                        // inside the token claims.
            }, 
            "init_data": {              // `init_data` is optional. If given, the init data binding will
                                        // be checked.
                                        // The field `raw` and `structured` are exclusive.
                "init_data_digest": "YWFhCg==...",  // Base64 encoded init data digest slice. The whole string will be base64
                                                    // decoded. The result one will then be accumulated into a digest which
                                                    // is used as the expected init data to check against the one inside
                                                    // evidence.
                                                    //
                                                    // The alphabet is URL_SAFE_NO_PAD.
                                                    // defined in https://datatracker.ietf.org/doc/html/rfc4648#section-5
                                        
                "init_data_toml": "algorithm = \"sha384\"..."       // Init data TOML. CoCoAS will perform hash calculation on the whole
                                                                    // to check against the one inside evidence. The hash algorithm to use
                                                                    // is inside the Initdata Toml's metadata.
                                                                    // 
                                                                    // See https://github.com/confidential-containers/trustee/blob/main/kbs/docs/initdata.md#toml-version
                                                                    // 
                                                                    // After the verification, the `.data` field of init data field will
                                                                    // be included inside the token claims.
            }, 
            "runtime_data_hash_algorithm": "sha384",// Hash algorithm used to calculate runtime data. Currently can be 
                                                    // "sha256", "sha384" or "sha512". If not specified, "sha384" will be selected.
            "init_data_hash_algorithm": "sha384",   // Hash algorithm used to calculate init data. Currently can be 
                                                    // "sha256", "sha384" or "sha512". If not specified, "sha384" will be selected.
        }
    ],
    "policy_ids": ["default", "policy-1"]           // List of IDs of the policy used to check evidence. If
                                                    // not provided, a "default" one will be used.
}
```
- `/policy`: receives policy setting request. The request POST payload is like
```json
{
    "type": "rego",         // policy type
    "policy_id": "yyyyy",   // raw string of policy id
    "policy": "xxxxx"       // base64 encoded policy content
}
```
- `/.well-known/jwks.json`: returns a JWK Set document for validating attestation tokens signed by this AS instance. Example response:
```json
{
    "keys": [
        {
            "alg": "ES256",
            "kty": "EC",
            "crv": "P-256",
            "x": "<base64url>",
            "y": "<base64url>"
        }
    ]
}
```


## Inference background check

Build the REST service with `restful-bin,tdx-verifier,tdx-self-attestation` and
start it with `--inference-only` and a TLS certificate/key. Set
`storage_backend.storage_type` to `Memory`, leave `rvps_config` at its default,
set the HTTPS `attestation_token_broker.issuer_name`, and populate
`attestation_token_broker.self_attestation` with the AS release manifest digest
and the approved governance snapshot. The policy hashes are the SHA-384 of the
exact built-in `ear_default_policy_cpu.rego` and
`ear_application_policy_cpu.rego` bytes. Their snapshot IDs are `default_cpu`
and `application_cpu`. Include all the reference values used by both policies.

For inference, set `governance.inference_releases` to an object keyed first by
the exact tenant-facing HTTPS audience and then by `release_id`. Each entry
requires `application_rtmr3` and `init_data_sha384`, both 96-character lowercase
hex digests present in the corresponding reference values. Assign distinct
audiences to services that require tenant isolation. The AS matches both
measured values against the same record before signing. Approve and distribute
the new governance digest with the tenant's trust and release files. Earlier
inference-only configurations require this new field before starting.
The launcher verifies the mounted release files and writes the RTMR3 event
before executing the server. The approved InitData must bind the actual launcher,
immutable filesystem, launch arguments, and restrictive agent policy.

The inference listener exposes `POST /v1/verify`, `/readyz` and `/healthz`.
A request contains `attestation_request` in the usual REST wire format, with
one native TDX report and both `default` and `application` policies. Use
SHA-384 structured runtime data with `profile` set to
`coco.inference-background-check.v1`. It includes `audience`, `release_id`,
`nonce`, `session_id` and `tls_spki_sha256`. Also supply the approved InitData
TOML and the complete CCEL. An optional `known_signer_kids` array lets the
selected replica omit its endorsement when the client has a valid cached copy.
A successful result is a JSON object with `ear` and optional
`signer_evidence`. Clients must verify both the signer and the fresh EAR
against local trust and the actual inference connection. Use 400 for invalid
requests and 422 for attestation or policy rejection. A temporary dependency
failure, deadline, or admission limit returns 503 with `Retry-After`.

Build the guest tools and client with the following commands.

```bash
cargo build --locked -p tdx-workload --features as-launch,inference-guest --bins
cargo build --locked -p trustee-attested-signer --features inference-cli --bins
```

Run `tdx-inference-guest` in the measured guest. Its backend must listen only on
the same guest's loopback interface and provide `GET /health` for readiness.
Supply the guest's certificate and key, measured workload event journal,
approved application RTMR3, audience and release ID. Provision a distinct
admission token using `--evidence-token-file` and a business credential using
`--token-file`. The evidence route accepts only the admission token. The client
sends the business credential and optional OpenAI-compatible request over the
same HTTPS connection after successful attestation. Only the admission token is
required for evidence-only clients.

```bash
verify-inference --trust signer-trust.json --release inference-release.json \
  --init-data approved-initdata.toml --evidence-token-file evidence-token \
  --token-file tenant-token \
  --prompt-request request.json
```

The local inference release file contains `audience` (the HTTPS origin),
`release_id`, `as_release_manifest_digest`, `governance_digest`, and
`policy_hashes` keyed by the wire policy IDs `default` and `application`.
Use `as-governance-digest --config <approved-config.json>` to calculate the
governance digest. The client accepts optional pinned `--guest-ca` and
`--as-ca` roots for private PKIs. The inference endpoint currently implements
the CPU plus application measurement profile. GPU evidence requires its own
combined appraisal profile.

The Trustee chart enables the separate deployment through `verifyAs.enabled`.
It uses the same `as.image.digest` as deployment AS, with
`--build-arg ENABLE_INFERENCE=true` in the gRPC image recipe. Provide the
native TDX runtime class, configuration/TLS/launch secrets, approved starting
RTMR3, and the launch-policy annotations. The launch Secret contains
`manifest.json` with profile `trustee.as-elf-load.v1`, the approved
`as_release_manifest_digest`, and a `files` array with `role`, canonical
absolute `path`, `size`, and `sha384` for each file. Use role
`restful-as` for the executable. Use `tdx-as-launch --print-measurement` to
compute the expected RTMR3 from the approved manifest.

For repeatable release binaries, run `hack/rebuild-as.sh` with the verified
source bundle, vendored Cargo inputs, published builder digest, commit, and
commit timestamp. The generated `expected-elf.sha384` covers all three
binaries. The shared Dockerfile can package these exact outputs with
`--build-arg ENABLE_INFERENCE=true --build-arg RELEASE_ELF_DIR=<context-path>`
after the release pipeline has verified the signed input and output manifests.
