# This rule gates the default CPU appraisal using native TDX evidence.
inference_executables := executables if {
	input.tdx.tcb_status == "UpToDate"
	hardware == 2
	configuration == 2
	executables in {3, 4}

	binding := input.runtime_data_claims
	regex.match("^[0-9a-f]{64}$", binding.nonce)
	regex.match("^[0-9a-f]{64}$", binding.tls_spki_sha256)

	rtmr3 := input.tdx.quote.body.rtmr_3
	valid_sha384(rtmr3)
	init_data := input.init_data
	valid_sha384(init_data)
	init_data == input.tdx.quote.body.mr_config_id
	count(input.init_data_claims.agent_policy_claims.containers) > 0

	release := query_reference_value("tdx_inference_releases")[binding.audience][binding.release_id]
	release.rtmr3 == rtmr3
	release.init_data_sha384 == init_data
} else := 33

valid_sha384(value) if {
	regex.match("^[0-9a-f]{96}$", value)
	regex.match("[1-9a-f]", value)
}
