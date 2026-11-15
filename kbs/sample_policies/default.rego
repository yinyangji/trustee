package policy

import rego.v1

default allow := false

# Example resource layout: default/<type>/<tag> and workload/<type>/<tag>.
# The resource owner chooses the required policy, never the client's selector.
required_policy := {"default": {"default"}, "workload": {"default", "application"}}

policy_results(cpu) := cpu["ear.trustee.policy-results"] if {
    is_array(cpu["ear.trustee.policy-results"])
} else := [{"policy_id": cpu["ear.appraisal-policy-id"], "status": cpu["ear.status"]}]

requirements_met(repo, ids) if {
    required_policy[repo] - ids == set()
}

workload_binding_present(repo, cpu) if {
    repo == "default"
} else if {
    repo == "workload"
    evidence := cpu["ear.veraison.annotated-evidence"]
    init := evidence.init_data
    is_string(init)
    regex.match("^[0-9a-f]+$", init)
    regex.match("[1-9a-f]", init)
    evidence.workload.version == 1
    init == evidence.workload.launch_digest
    is_array(evidence.init_data_claims.agent_policy_claims.containers)
    count(evidence.init_data_claims.agent_policy_claims.containers) > 0
}

allow if {
    data.plugin == "resource"
    count(data["resource-path"]) == 3
    cpu := input.submods.cpu0
    results := policy_results(cpu)
    count(results) > 0
    every result in results {
        result.status == "affirming"
    }
    ids := {result.policy_id | some result in results}
    requirements_met(data["resource-path"][0], ids)
    workload_binding_present(data["resource-path"][0], cpu)
    cpu["ear.status"] == "affirming"
    evidence := cpu["ear.veraison.annotated-evidence"]
    some tee in {"tdx", "sgx", "snp", "csv", "cca", "se", "tpm", "az-tdx-vtpm", "az-snp-vtpm"}
    is_object(evidence[tee])
    not evidence.sample
    not evidence["sample-device"]
    vector := cpu["ear.trustworthiness-vector"]
    vector.executables in {2, 3, 4}
    vector.hardware == 2
    vector.configuration in {2, 3}
}
