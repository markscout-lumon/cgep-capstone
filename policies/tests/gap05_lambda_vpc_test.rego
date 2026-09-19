# policies/tests/gap05_lambda_vpc_test.rego
package compliance.hipaa.gap05_lambda_vpc_test

import rego.v1
import data.compliance.hipaa.gap05_lambda_vpc as gap05

compliant_function := {"resource_changes": [{
	"address": "aws_lambda_function.intake",
	"type": "aws_lambda_function",
	"change": {
		"actions": ["create"],
		"after": {
			"function_name": "intake-test",
			"vpc_config": [{
				"subnet_ids": ["subnet-aaa", "subnet-bbb"],
				"security_group_ids": ["sg-lambda"],
			}],
		},
	},
}]}

gap_function := {"resource_changes": [{
	"address": "aws_lambda_function.intake",
	"type": "aws_lambda_function",
	"change": {"actions": ["create"], "after": {"function_name": "intake-test"}},
}]}

empty_vpc_function := {"resource_changes": [{
	"address": "aws_lambda_function.intake",
	"type": "aws_lambda_function",
	"change": {
		"actions": ["create"],
		"after": {
			"function_name": "intake-test",
			"vpc_config": [{"subnet_ids": [], "security_group_ids": []}],
		},
	},
}]}

test_compliant_function_passes if {
	count(gap05.deny) == 0 with input as compliant_function
}

test_gap_function_fails if {
	some msg in gap05.deny with input as gap_function
	contains(msg, "5.3.5")
}

test_empty_vpc_config_fails if {
	some msg in gap05.deny with input as empty_vpc_function
	contains(msg, "5.3.5")
}
