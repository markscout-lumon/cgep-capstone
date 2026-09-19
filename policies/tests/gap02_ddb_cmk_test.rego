# policies/tests/gap02_ddb_cmk_test.rego
package compliance.hipaa.gap02_ddb_cmk_test

import rego.v1
import data.compliance.hipaa.gap02_ddb_cmk as gap02

compliant_table := {"resource_changes": [{
	"address": "aws_dynamodb_table.intake",
	"type": "aws_dynamodb_table",
	"change": {
		"actions": ["create"],
		"after": {
			"name": "intake-test",
			"server_side_encryption": [{
				"enabled": true,
				"kms_key_arn": "arn:aws:kms:us-east-1:123456789012:key/abcd",
			}],
		},
	},
}]}

gap_table := {"resource_changes": [{
	"address": "aws_dynamodb_table.intake",
	"type": "aws_dynamodb_table",
	"change": {"actions": ["create"], "after": {"name": "intake-test"}},
}]}

aws_owned_table := {"resource_changes": [{
	"address": "aws_dynamodb_table.intake",
	"type": "aws_dynamodb_table",
	"change": {
		"actions": ["create"],
		"after": {
			"name": "intake-test",
			"server_side_encryption": [{"enabled": true, "kms_key_arn": ""}],
		},
	},
}]}

test_compliant_table_passes if {
	count(gap02.deny) == 0 with input as compliant_table
}

test_gap_table_fails if {
	some msg in gap02.deny with input as gap_table
	contains(msg, "5.3.1")
}

test_aws_owned_key_fails if {
	some msg in gap02.deny with input as aws_owned_table
	contains(msg, "5.3.1")
}
