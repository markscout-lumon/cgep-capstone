######################################################################
# Hardening — gap-closing overrides on the starter workload.
# Sibling resources attach to the inherited bucket / VPC by reference.
# Nested blocks cannot live here; they stay on the original resource
# in main.tf. See GAP-MAP.md for the full location table.
#
# GAP register
# -----------
# GAP-01  ADDRESSED here + kms.tf
#         Original: main.tf aws_s3_bucket.uploads (default SSE-S3).
#         Fix: aws_s3_bucket_server_side_encryption_configuration below,
#         key = aws_kms_key.phi in kms.tf. Policy: detect SSE-KMS+CMK.
#
# GAP-02  ADDRESSED in main.tf + kms.tf (not a sibling resource)
#         Original: main.tf aws_dynamodb_table.intake (AWS-owned key).
#         Fix: nested server_side_encryption { kms_key_arn } on the table.
#         Policy: detect customer kms_key_arn.
#
# GAP-03  NOT ADDRESSED in Terraform — policy detect only
#         Original: main.tf aws_s3_bucket.uploads (no TLS deny).
#         No aws_s3_bucket_policy here. Suite must fail if
#         aws:SecureTransport deny is missing.
#
# GAP-04  ADDRESSED here
#         Original: main.tf aws_s3_bucket.uploads (versioning off).
#         Fix: aws_s3_bucket_versioning below. Policy: detect Enabled.
#
# GAP-05  ADDRESSED here — SG here, vpc_config nested in main.tf
#         Original: main.tf aws_lambda_function.intake (no VPC).
#         Fix: vpc_config on the function + aws_security_group.lambda below.
#         Still missing: AWSLambdaVPCAccessExecutionRole, NAT or endpoints.
#         Policy: detect vpc_config.
#
# GAP-06  NOT ADDRESSED — out of scope
#         Original: main.tf aws_lambda_function.intake
#         (no reserved concurrency, DLQ, or X-Ray).
#
# GAP-07  NOT ADDRESSED — out of scope
#         Original: main.tf aws_iam_role_policy.lambda_inline
#         (dynamodb:* and s3:* still present).
#
# GAP-08  NOT ADDRESSED — out of scope
#         Original: main.tf aws_apigatewayv2_stage.default
#         (no access logs, throttling, or WAF).
######################################################################

# GAP-01: SSE-KMS with the customer CMK (not default SSE-S3).
resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
    bucket_key_enabled = true
  }
}

# GAP-03: left open. No aws:SecureTransport deny; policy suite is expected
# to fail the plan if this gap is re-introduced or still present.

# GAP-04: versioning so PHI overwrites are recoverable.
resource "aws_s3_bucket_versioning" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  versioning_configuration {
    status = "Enabled"
  }
}

# GAP-05: egress-only security group for Lambda ENIs.
# vpc_config itself is nested on aws_lambda_function.intake in main.tf.
resource "aws_security_group" "lambda" {
  name        = "${local.name_prefix}-lambda-${local.suffix}"
  description = "Egress-only SG for intake Lambda ENIs"
  vpc_id      = aws_vpc.main.id

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
