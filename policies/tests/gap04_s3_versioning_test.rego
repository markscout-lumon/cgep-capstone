# policies/tests/gap04_s3_versioning_test.rego
package compliance.hipaa.gap04_s3_versioning_test

import rego.v1
import data.compliance.hipaa.gap04_s3_versioning as gap04

compliant_bucket := {"resource_changes": [
	{
		"address": "aws_s3_bucket.uploads",
		"type": "aws_s3_bucket",
		"change": {"actions": ["create"], "after": {"bucket": "uploads-test"}},
	},
	{
		"address": "aws_s3_bucket_versioning.uploads",
		"type": "aws_s3_bucket_versioning",
		"change": {
			"actions": ["create"],
			"after": {
				"bucket": "uploads-test",
				"versioning_configuration": [{"status": "Enabled"}],
			},
		},
	},
]}

gap_bucket := {"resource_changes": [{
	"address": "aws_s3_bucket.uploads",
	"type": "aws_s3_bucket",
	"change": {"actions": ["create"], "after": {"bucket": "uploads-test"}},
}]}

suspended_bucket := {"resource_changes": [
	{
		"address": "aws_s3_bucket.uploads",
		"type": "aws_s3_bucket",
		"change": {"actions": ["create"], "after": {"bucket": "uploads-test"}},
	},
	{
		"address": "aws_s3_bucket_versioning.uploads",
		"type": "aws_s3_bucket_versioning",
		"change": {
			"actions": ["create"],
			"after": {
				"bucket": "uploads-test",
				"versioning_configuration": [{"status": "Suspended"}],
			},
		},
	},
]}

test_compliant_bucket_passes if {
	count(gap04.deny) == 0 with input as compliant_bucket
}

test_gap_bucket_fails if {
	some msg in gap04.deny with input as gap_bucket
	contains(msg, "5.1.7")
}

test_suspended_versioning_fails if {
	some msg in gap04.deny with input as suspended_bucket
	contains(msg, "5.1.7")
}
