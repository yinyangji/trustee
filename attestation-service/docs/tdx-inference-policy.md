# Native TDX inference with a single policy

Use this profile with the standard AS `POST /attestation` endpoint. It evaluates the
default CPU checks and the application baseline in one policy. Image decryption
continues to use the deployment's existing KBS policy selection. The dedicated
[AS self-attestation profile](restful-as.md#inference-background-check) is available
for clients that require remote proof of the verifier and its signing key.

## Policy and reference values

Generate the policy from the same Trustee revision used by AS. The generator takes
the CPU policy from that revision, so its boot rules can follow upstream updates.

```sh
python3 hack/build-tdx-inference-policy.py > tdx_inference_cpu.rego
```

Register the generated policy as `tdx_inference_cpu` using the existing
[policy administration interface](restful-as.md#api). Install it where every
inference AS replica can read it. Restrict administrative policy and RVPS writes to
deployment operators.

Publish `tdx_inference_releases` as a JSON object in the RVPS used by that AS. Each
entry pairs the expected contents of RTMR3 with the InitData digest for the same
approved release and service. Register it with the normal RVPS provenance workflow
under that key. Keep the rest of the CPU reference values in their existing entries.

```json
{
  "https://inference.example": {
    "release-1": {
      "rtmr3": "<96 lowercase hex digits>",
      "init_data_sha384": "<96 lowercase hex digits>"
    }
  }
}
```

Keep the existing CPU reference values for the supported boot path. The inference
profile additionally requires current TDX collateral, an `UpToDate` TCB, disabled
debugging, and SHA-384 InitData bound by MRCONFIGID. Calculate RTMR3 using the
approved guest boot and runtime measurement sequence. Use the trusted guest loader
to measure the files actually loaded, with InitData binding the restrictive guest
policy. RTMR3 represents the complete extend sequence.

## Attestation request

For each verification, generate a fresh, random 32-byte nonce. On the inference
connection, calculate SHA-256 over the DER SubjectPublicKeyInfo of the peer's TLS
key. Use lowercase hex for both values. The guest derives the key digest from its
own serving certificate and keeps the corresponding private key inside the guest.
The guest attests to the SHA-384 digest of the canonical JSON binding containing
the nonce, TLS key digest, service audience, and release. Submit the evidence as
unpadded base64url and the same binding as `runtime_data.structured`.

```json
{
  "policy_ids": ["tdx_inference"],
  "verification_requests": [{
    "tee": "tdx",
    "evidence": "<base64url evidence>",
    "init_data": {"init_data_toml": "<approved InitData TOML>"},
    "runtime_data_hash_algorithm": "sha384",
    "runtime_data": {
      "structured": {
        "audience": "https://inference.example",
        "release_id": "release-1",
        "nonce": "<64 lowercase hex digits>",
        "tls_spki_sha256": "<64 lowercase hex digits>"
      }
    }
  }]
}
```

Before sending inference data, verify the EAR signature against the trusted AS
issuer and key, check its validity and the `tdx_inference` policy ID, require an
affirming native TDX CPU appraisal, and compare the signed runtime data with the
values for the current request and TLS connection. Use the same verified connection
for inference.
