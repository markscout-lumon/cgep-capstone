# METADATA
# title: 5.3.5 — Intake Lambda runs in the provisioned VPC
# custom:
#   framework: hipaa
#   catalog: nist-sp-800-66-rev2
#   gap: GAP-05
#   controls:
#     - "164.312(e)(1)"
#   sp_800_66:
#     - "5.3.5"
#   severity: high
package compliance.hipaa.gap05_lambda_vpc

import rego.v1

deny contains msg if {
	some fn in intake_functions
	not function_in_vpc(fn)
	msg := sprintf(
		"[5.3.5] %s: Lambda has no vpc_config. Place the function in private subnets with a security group.",
		[fn.address],
	)
}

intake_functions contains fn if {
	some fn in input.resource_changes
	fn.type == "aws_lambda_function"
	fn.address == "aws_lambda_function.intake"
	not "delete" in fn.change.actions
}

function_in_vpc(fn) if {
	cfg := fn.change.after.vpc_config[_]
	count(cfg.subnet_ids) > 0
	count(cfg.security_group_ids) > 0
}
