variable "aws_region" {
  type        = string
  description = "AWS region for the starter."
  default     = "us-east-1"
}

#Adding Global variables
variable "project_name" {
  type    = string
  default = "acme-health-intake"
}

variable "lock_mode" {
  type    = string
  default = "GOVERNANCE" # Set to governance mode for non-production environments
}

variable "retention_days" {
  type    = number
  default = 30
}