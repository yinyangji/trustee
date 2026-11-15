package policy

import rego.v1

# Compose with default_cpu: this policy asserts only the application dimension.
# RTMR[3] is meaningful only behind an approved, launch-bound enforcement policy.
default executables := 33

executables := 2 if {
    trusted_measurement_environment
    rtmr := input.tdx.quote.body.rtmr_3
    is_string(rtmr)
    regex.match("^[0-9a-f]{96}$", rtmr)
    rtmr != "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    rtmr in query_reference_value("application_rtmr_3")
}

# AS exposes these structured claims only after validating the supplied Init-Data
# against the signed quote's MRCONFIGID. The RVPS value must endorse a restrictive
# Agent Policy and its immutable images/dependencies, not a permissive lab Pod.
# A runtime-data boolean or an RTMR event supplied by the requester is NOT a trust anchor.
trusted_measurement_environment if {
    init := input.init_data
    is_string(init)
    regex.match("^[0-9a-f]{96}$", init)
    init != "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    init == input.tdx.quote.body.mr_config_id
    init in query_reference_value("application_init_data")
    policy := input.init_data_claims.agent_policy_claims
    is_object(policy)
    is_array(policy.containers)
    count(policy.containers) > 0
}

trust_claims := {"executables": executables}
