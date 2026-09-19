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
# GAP-03  ADDRESSED here (passing-gate PR)
#         Original: main.tf aws_s3_bucket.uploads (no TLS deny).
#         Fix: aws_s3_bucket_policy.uploads Deny when
#         aws:SecureTransport is false. Policy: detect that statement.
#
# GAP-04  ADDRESSED here
#         Original: main.tf aws_s3_bucket.uploads (versioning off).
#         Fix: aws_s3_bucket_versioning below. Policy: detect Enabled.
#
# GAP-05  ADDRESSED here — SG here, vpc_config nested in main.tf
#         Original: main.tf aws_lambda_function.intake (no VPC).
#         Fix: vpc_config on the function + aws_security_group.lambda below.
#         ENI IAM attached. Still missing: NAT or VPC endpoints.
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

# GAP-03: deny HTTP to the uploads bucket (HIPAA 164.312(e)(1) / 800-66 5.3.5).
resource "aws_s3_bucket_policy" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        aws_s3_bucket.uploads.arn,
        "${aws_s3_bucket.uploads.arn}/*",
      ]
      Condition = {
        Bool = { "aws:SecureTransport" = "false" }
      }
    }]
  })
}

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
