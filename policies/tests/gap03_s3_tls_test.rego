# policies/tests/gap03_s3_tls_test.rego
package compliance.hipaa.gap03_s3_tls_test

import rego.v1
import data.compliance.hipaa.gap03_s3_tls as gap03

tls_deny_policy := json.marshal({
	"Version": "2012-10-17",
	"Statement": [{
		"Sid": "DenyInsecureTransport",
		"Effect": "Deny",
		"Principal": "*",
		"Action": "s3:*",
		"Resource": ["arn:aws:s3:::uploads-test", "arn:aws:s3:::uploads-test/*"],
		"Condition": {"Bool": {"aws:SecureTransport": "false"}},
	}],
})

compliant_bucket := {"resource_changes": [
	{
		"address": "aws_s3_bucket.uploads",
		"type": "aws_s3_bucket",
		"change": {"actions": ["create"], "after": {"bucket": "uploads-test"}},
	},
	{
		"address": "aws_s3_bucket_policy.uploads",
		"type": "aws_s3_bucket_policy",
		"change": {
			"actions": ["create"],
			"after": {"bucket": "uploads-test", "policy": tls_deny_policy},
		},
	},
]}

gap_bucket := {"resource_changes": [{
	"address": "aws_s3_bucket.uploads",
	"type": "aws_s3_bucket",
	"change": {"actions": ["create"], "after": {"bucket": "uploads-test"}},
}]}

allow_only_policy := json.marshal({
	"Version": "2012-10-17",
	"Statement": [{
		"Effect": "Allow",
		"Principal": "*",
		"Action": "s3:*",
		"Resource": "arn:aws:s3:::uploads-test/*",
	}],
})

allow_only_bucket := {"resource_changes": [
	{
		"address": "aws_s3_bucket.uploads",
		"type": "aws_s3_bucket",
		"change": {"actions": ["create"], "after": {"bucket": "uploads-test"}},
	},
	{
		"address": "aws_s3_bucket_policy.uploads",
		"type": "aws_s3_bucket_policy",
		"change": {
			"actions": ["create"],
			"after": {"bucket": "uploads-test", "policy": allow_only_policy},
		},
	},
]}

test_compliant_bucket_passes if {
	count(gap03.deny) == 0 with input as compliant_bucket
}

test_gap_bucket_fails if {
	some msg in gap03.deny with input as gap_bucket
	contains(msg, "5.3.5")
}

test_allow_only_policy_fails if {
	some msg in gap03.deny with input as allow_only_bucket
	contains(msg, "5.3.5")
}
