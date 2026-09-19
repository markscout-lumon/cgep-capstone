# METADATA
# title: 5.3.5 — S3 bucket policy denies non-TLS
# custom:
#   framework: hipaa
#   catalog: nist-sp-800-66-rev2
#   gap: GAP-03
#   controls:
#     - "164.312(e)(1)"
#   sp_800_66:
#     - "5.3.5"
#   severity: high
package compliance.hipaa.gap03_s3_tls

import rego.v1

deny contains msg if {
	some bucket in phi_buckets
	not bucket_denies_insecure_transport(bucket)
	msg := sprintf(
		"[5.3.5] %s: bucket policy does not deny non-TLS (aws:SecureTransport=false). Add an aws_s3_bucket_policy Deny for HTTP.",
		[bucket.address],
	)
}

phi_buckets contains bucket if {
	some bucket in input.resource_changes
	bucket.type == "aws_s3_bucket"
	bucket.address == "aws_s3_bucket.uploads"
	not "delete" in bucket.change.actions
}

bucket_denies_insecure_transport(bucket) if {
	some pol in input.resource_changes
	pol.type == "aws_s3_bucket_policy"
	not "delete" in pol.change.actions
	policy_targets_bucket(pol, bucket)
	some stmt in policy_statements(pol)
	statement_denies_http(stmt)
}

policy_targets_bucket(pol, bucket) if {
	pol.change.after.bucket == bucket.change.after.bucket
}

policy_targets_bucket(pol, bucket) if {
	pol.change.after.bucket == bucket.address
}

policy_statements(pol) := stmts if {
	doc := json.unmarshal(pol.change.after.policy)
	stmts := statement_list(doc)
}

policy_statements(pol) := stmts if {
	is_object(pol.change.after.policy)
	stmts := statement_list(pol.change.after.policy)
}

statement_list(doc) := doc.Statement if {
	is_array(doc.Statement)
}

statement_list(doc) := [doc.Statement] if {
	is_object(doc.Statement)
}

statement_denies_http(stmt) if {
	stmt.Effect == "Deny"
	secure_transport_false(stmt)
}

secure_transport_false(stmt) if {
	val := object.get(object.get(stmt, "Condition", {}), "Bool", {})["aws:SecureTransport"]
	falsey(val)
}

falsey(val) if val == false
falsey(val) if val == "false"
falsey(val) if val == ["false"]
falsey(val) if val == [false]
