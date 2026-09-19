# METADATA
# title: 5.1.7 — S3 versioning enabled for PHI recoverability
# custom:
#   framework: hipaa
#   catalog: nist-sp-800-66-rev2
#   gap: GAP-04
#   controls:
#     - "164.308(a)(7)"
#   sp_800_66:
#     - "5.1.7"
#   severity: high
package compliance.hipaa.gap04_s3_versioning

import rego.v1

deny contains msg if {
	some bucket in phi_buckets
	not bucket_versioning_enabled(bucket)
	msg := sprintf(
		"[5.1.7] %s: versioning is not Enabled. Add aws_s3_bucket_versioning with status = \"Enabled\".",
		[bucket.address],
	)
}

phi_buckets contains bucket if {
	some bucket in input.resource_changes
	bucket.type == "aws_s3_bucket"
	bucket.address == "aws_s3_bucket.uploads"
	not "delete" in bucket.change.actions
}

bucket_versioning_enabled(bucket) if {
	some ver in input.resource_changes
	ver.type == "aws_s3_bucket_versioning"
	not "delete" in ver.change.actions
	versioning_targets_bucket(ver, bucket)
	ver.change.after.versioning_configuration[_].status == "Enabled"
}

versioning_targets_bucket(ver, bucket) if {
	ver.change.after.bucket == bucket.change.after.bucket
}

versioning_targets_bucket(ver, bucket) if {
	ver.change.after.bucket == bucket.address
}
