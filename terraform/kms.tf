######################################################################
# KMS — customer-owned CMK for PHI data stores (GAP-01, GAP-02).
######################################################################

resource "aws_kms_key" "phi" {
  description             = "CMK for PHI data stores"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = 30
}
