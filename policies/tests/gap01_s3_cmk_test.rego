# policies/tests/gap01_s3_cmk_test.rego
package compliance.hipaa.gap01_s3_cmk_test

import rego.v1
import data.compliance.hipaa.gap01_s3_cmk as gap01

compliant_bucket := {"resource_changes": [
	{
		"address": "aws_s3_bucket.uploads",
		"type": "aws_s3_bucket",
		"change": {"actions": ["create"], "after": {"bucket": "uploads-test"}},
	},
	{
		"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
		"type": "aws_s3_bucket_server_side_encryption_configuration",
		"change": {
			"actions": ["create"],
			"after": {
				"bucket": "uploads-test",
				"rule": [{"apply_server_side_encryption_by_default": [{
					"sse_algorithm": "aws:kms",
					"kms_master_key_id": "arn:aws:kms:us-east-1:123456789012:key/abcd",
				}]}],
			},
		},
	},
]}

gap_bucket := {"resource_changes": [{
	"address": "aws_s3_bucket.uploads",
	"type": "aws_s3_bucket",
	"change": {"actions": ["create"], "after": {"bucket": "uploads-test"}},
}]}

sse_s3_bucket := {"resource_changes": [
	{
		"address": "aws_s3_bucket.uploads",
		"type": "aws_s3_bucket",
		"change": {"actions": ["create"], "after": {"bucket": "uploads-test"}},
	},
	{
		"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
		"type": "aws_s3_bucket_server_side_encryption_configuration",
		"change": {
			"actions": ["create"],
			"after": {
				"bucket": "uploads-test",
				"rule": [{"apply_server_side_encryption_by_default": [{
					"sse_algorithm": "AES256",
					"kms_master_key_id": "",
				}]}],
			},
		},
	},
]}

test_compliant_bucket_passes if {
	count(gap01.deny) == 0 with input as compliant_bucket
}

test_gap_bucket_fails if {
	some msg in gap01.deny with input as gap_bucket
	contains(msg, "5.3.1")
}

test_sse_s3_bucket_fails if {
	some msg in gap01.deny with input as sse_s3_bucket
	contains(msg, "5.3.1")
}