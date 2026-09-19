# METADATA
# title: 5.3.1 — DynamoDB PHI encryption uses a customer CMK
# custom:
#   framework: hipaa
#   catalog: nist-sp-800-66-rev2
#   gap: GAP-02
#   controls:
#     - "164.312(a)(2)(iv)"
#   sp_800_66:
#     - "5.3.1"
#   severity: high
package compliance.hipaa.gap02_ddb_cmk

import rego.v1

deny contains msg if {
	some table in phi_tables
	not table_has_cmk(table)
	msg := sprintf(
		"[5.3.1] %s: DynamoDB encryption is not a customer CMK. Set server_side_encryption { enabled = true, kms_key_arn = <cmk> }.",
		[table.address],
	)
}

phi_tables contains table if {
	some table in input.resource_changes
	table.type == "aws_dynamodb_table"
	table.address == "aws_dynamodb_table.intake"
	not "delete" in table.change.actions
}

table_has_cmk(table) if {
	enc := table.change.after.server_side_encryption[_]
	enc.enabled == true
	is_string(enc.kms_key_arn)
	enc.kms_key_arn != ""
	not startswith(enc.kms_key_arn, "alias/aws/")
}
