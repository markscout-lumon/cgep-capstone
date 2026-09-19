# Gap location and remediation map

Companion to [GAPS.md](GAPS.md). Original gaps live on the inherited workload in `terraform/main.tf`. Corrections that *can* be sibling resources live in `terraform/kms.tf` and `terraform/hardening.tf`. Nested blocks (DynamoDB encryption, Lambda `vpc_config`) have to stay on the original resource.

Policy column is **enforced**. `policies/gap01_*.rego` through `gap05_*.rego` run in CI via `scripts/policy-gate.sh`.

In scope for this submission: **GAP-01 through GAP-05**. GAP-06 through GAP-08 are deferred.

## In scope

| Gap | Original location | What was wrong | Terraform correction | Policy |
|---|---|---|---|---|
| **GAP-01** | `terraform/main.tf` → `aws_s3_bucket.uploads` | Bucket uses default SSE-S3. No customer CMK. | **Closed.** CMK: `terraform/kms.tf` → `aws_kms_key.phi`. Bucket encryption: `terraform/hardening.tf` → `aws_s3_bucket_server_side_encryption_configuration.uploads` (`sse_algorithm = "aws:kms"`, `kms_master_key_id = aws_kms_key.phi.arn`). | **Detect.** Fail the plan if default encryption is not SSE-KMS with a CMK ARN. |
| **GAP-02** | `terraform/main.tf` → `aws_dynamodb_table.intake` | Table uses the AWS-owned default key. | **Closed (nested).** `server_side_encryption` on the same table in `terraform/main.tf`, `kms_key_arn = aws_kms_key.phi.arn`. Cannot be a sibling resource. Key remains in `terraform/kms.tf`. | **Detect.** Fail the plan if the table has no customer `kms_key_arn`. |
| **GAP-03** | `terraform/main.tf` → `aws_s3_bucket.uploads` | No bucket policy denying `aws:SecureTransport = false`. | **Closed** on the passing-gate PR. `terraform/hardening.tf` → `aws_s3_bucket_policy.uploads` (`Deny` when `aws:SecureTransport` is false). PR #1 left this open so the gate failed. | **Detect.** Fail the plan if the uploads bucket has no TLS-deny statement. |
| **GAP-04** | `terraform/main.tf` → `aws_s3_bucket.uploads` | Versioning off. PHI overwrites are unrecoverable. | **Closed.** `terraform/hardening.tf` → `aws_s3_bucket_versioning.uploads` (`status = "Enabled"`). | **Detect.** Fail the plan if versioning is not `Enabled`. |
| **GAP-05** | `terraform/main.tf` → `aws_lambda_function.intake` | Function runs in the default Lambda network, not the starter VPC. | **Partial.** `vpc_config` nested on `aws_lambda_function.intake` in `terraform/main.tf` (private subnets). SG: `terraform/hardening.tf` → `aws_security_group.lambda`. ENI IAM (`AWSLambdaVPCAccessExecutionRole`) is attached. Still missing NAT or VPC endpoints. | **Detect.** Fail the plan if the function has no `vpc_config`. |

## Out of scope (next sprint)

| Gap | Original location | What was wrong | Terraform correction | Policy |
|---|---|---|---|---|
| **GAP-06** | `terraform/main.tf` → `aws_lambda_function.intake` | No reserved concurrency, DLQ, or X-Ray. | **None.** Starter left as-is. | **Not in this submission.** |
| **GAP-07** | `terraform/main.tf` → `aws_iam_role_policy.lambda_inline` | `dynamodb:*` and `s3:*` on the workload stores. | **None.** Starter left as-is. | **Not in this submission.** |
| **GAP-08** | `terraform/main.tf` → `aws_apigatewayv2_stage.default` | No access logs, throttling, or WAF. | **None.** Starter left as-is. | **Not in this submission.** |

## File cheat sheet

| File | Role |
|---|---|
| `terraform/main.tf` | Inherited workload. Original gap sites. Nested fixes: DynamoDB SSE (GAP-02), Lambda `vpc_config` (GAP-05). |
| `terraform/kms.tf` | Shared PHI CMK used by GAP-01 and GAP-02. |
| `terraform/hardening.tf` | Sibling overrides: S3 SSE-KMS (GAP-01), TLS deny (GAP-03), S3 versioning (GAP-04), Lambda SG (GAP-05). |
| `policies/*.rego` | Conftest detectors for GAP-01 through GAP-05. Unit tests in `policies/tests/`. |

## Why some fixes are not in `hardening.tf`

Terraform maps one resource type to one AWS API. S3 encryption and versioning are separate APIs, so they can attach to `aws_s3_bucket.uploads` by `bucket = ...` from `hardening.tf`. DynamoDB encryption and Lambda VPC config are nested blocks on the original resource; they cannot be declared as new files without moving the whole table or function.
