# METADATA
# title: 5.3.1 — S3 PHI encryption uses a customer CMK
# custom:
#   framework: hipaa
#   catalog: nist-sp-800-66-rev2
#   gap: GAP-01
#   controls:
#     - "164.312(a)(2)(iv)"
#   sp_800_66:
#     - "5.3.1"
#   severity: high
package compliance.hipaa.gap01_s3_cmk

import rego.v1

deny contains msg if {
	some bucket in phi_buckets
	not bucket_has_cmk_sse(bucket)
	msg := sprintf(
		"[5.3.1] %s: default encryption is not SSE-KMS with a customer CMK. Add aws_s3_bucket_server_side_encryption_configuration with sse_algorithm=\"aws:kms\" and kms_master_key_id set to your CMK.",
		[bucket.address],
	)
}
phi_buckets contains bucket if {
	some bucket in input.resource_changes
	bucket.type == "aws_s3_bucket"
	bucket.address == "aws_s3_bucket.uploads"
	not "delete" in bucket.change.actions
}
bucket_has_cmk_sse(bucket) if {
	some enc in input.resource_changes
	enc.type == "aws_s3_bucket_server_side_encryption_configuration"
	not "delete" in enc.change.actions
	enc_targets_bucket(enc, bucket)
	def := enc.change.after.rule[_].apply_server_side_encryption_by_default[_]
	def.sse_algorithm == "aws:kms"
	cmk_id_present(def)
}
enc_targets_bucket(enc, bucket) if {
	enc.change.after.bucket == bucket.change.after.bucket
}
enc_targets_bucket(enc, bucket) if {
	enc.change.after.bucket == bucket.address
}
cmk_id_present(def) if {
	is_string(def.kms_master_key_id)
	def.kms_master_key_id != ""
	not startswith(def.kms_master_key_id, "alias/aws/")
}
