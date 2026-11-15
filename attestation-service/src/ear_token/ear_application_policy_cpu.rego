package policy

import rego.v1

# Compose with default_cpu: this policy asserts only the application dimension.
# RTMR[3] is meaningful only behind an approved, launch-bound enforcement policy.
default executables := 33

executables := 2 if {
    trusted_measurement_environment
    binding := input.workload
    binding.version == 1
    valid_digest(binding.measurement, binding.measurement_algorithm)
    binding.measurement in query_reference_value(binding.reference_id)
}

# AS exposes these structured claims only after validating the supplied Init-Data
# against the signed quote's MRCONFIGID. The RVPS value must endorse a restrictive
# Agent Policy and its immutable images/dependencies, not a permissive lab Pod.
# A runtime-data boolean or an RTMR event supplied by the requester is NOT a trust anchor.
trusted_measurement_environment if {
    init := input.init_data
    valid_digest(init, input.workload.launch_algorithm)
    init == input.workload.launch_digest
    init in query_reference_value("application_init_data")
    policy := input.init_data_claims.agent_policy_claims
    is_object(policy)
    is_array(policy.containers)
    count(policy.containers) > 0
}

trust_claims := {"executables": executables}

valid_digest(value, algorithm) if {
    lengths := {"sha256": 64, "sha384": 96, "sha512": 128}
    is_string(value)
    count(value) == lengths[algorithm]
    regex.match("^[0-9a-f]+$", value)
    regex.match("[1-9a-f]", value)
}
