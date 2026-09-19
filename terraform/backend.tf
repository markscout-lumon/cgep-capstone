# Literal names — Terraform backends cannot interpolate variables.
# Must match terraform/tfstate.tf.
terraform {
  backend "s3" {
    bucket         = "acme-health-intake-tfstate-140421379759"
    key            = "capstone/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "acme-health-intake-tfstate-lock"
    encrypt        = true
  }
}
