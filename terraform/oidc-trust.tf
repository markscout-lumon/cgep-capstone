# terraform/primitives/oidc-trust/main.tf
variable "github_org"  { type = string }
variable "github_repo" { type = string }

# Account already has the GitHub Actions OIDC provider (409 if we create again).
# Look it up; do not own or destroy the account-level provider.
data "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"
}

resource "aws_iam_role" "grc_gate" {
  name = "cgep-grc-gate"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = data.aws_iam_openid_connect_provider.github.arn }
      Action    = ["sts:AssumeRoleWithWebIdentity", "sts:TagSession"]
      Condition = {
        StringEquals = { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" }
        # This GitHub account has immutable-ID subject claims enabled, so the
        # sub claim is "repo:OWNER@ownerId/REPO@repoId:*" instead of the
        # classic "repo:OWNER/REPO:*". Match both so the trust scope stays
        # limited to this one repo either way.
        StringLike = {
          "token.actions.githubusercontent.com:sub" = [
            "repo:${var.github_org}/${var.github_repo}:*",
            "repo:${var.github_org}@*/${var.github_repo}@*:*",
          ]
        }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "readonly" {
  role       = aws_iam_role.grc_gate.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# Plan needs ReadOnlyAccess plus DynamoDB lock / S3 state writes.
# Apply-on-merge needs to manage this root module. One role, because
# the workflow assumes a single AWS_ROLE_ARN. Scoped to this stack's
# services, not AdministratorAccess.
resource "aws_iam_role_policy" "grc_gate_apply" {
  name = "cgep-grc-gate-apply"
  role = aws_iam_role.grc_gate.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "TerraformState"
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
        ]
        Resource = [
          aws_s3_bucket.tfstate.arn,
          "${aws_s3_bucket.tfstate.arn}/*",
        ]
      },
      {
        Sid    = "TerraformLock"
        Effect = "Allow"
        Action = [
          "dynamodb:DescribeTable",
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:DeleteItem",
        ]
        Resource = aws_dynamodb_table.tfstate_lock.arn
      },
      {
        Sid    = "EvidenceVault"
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetBucketLocation",
          "s3:GetBucketVersioning",
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:GetObjectRetention",
          "s3:PutObject",
          "s3:PutObjectRetention",
        ]
        Resource = [
          aws_s3_bucket.vault.arn,
          "${aws_s3_bucket.vault.arn}/*",
        ]
      },
      {
        Sid      = "ApplyStack"
        Effect   = "Allow"
        Action   = [
          "apigateway:*",
          "cloudtrail:*",
          "dynamodb:*",
          "ec2:*",
          "iam:*",
          "kms:*",
          "lambda:*",
          "logs:*",
          "s3:*",
          "sts:GetCallerIdentity",
        ]
        Resource = "*"
      }
    ]
  })
}

output "role_arn" { value = aws_iam_role.grc_gate.arn }
