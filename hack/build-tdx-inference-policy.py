#!/usr/bin/env python3

"""Generate the native TDX inference policy using this checkout's default CPU policy."""

from pathlib import Path
import sys


def main() -> None:
    attestation_service = Path(__file__).resolve().parents[1] / "attestation-service"
    default_policy = attestation_service / "src/ear_token/ear_default_policy_cpu.rego"
    inference_rules = attestation_service / "policies/tdx_inference.rego.inc"
    policy = default_policy.read_text(encoding="utf-8")
    executables_claim = '"executables": executables,'
    if policy.count(executables_claim) != 1:
        sys.exit("The default CPU policy changed. Review the inference policy before generating it.")

    generated = policy.replace(executables_claim, '"executables": inference_executables,')
    sys.stdout.write(generated.rstrip() + "\n\n" + inference_rules.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
