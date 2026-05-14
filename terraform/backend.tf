# Terraform Backend Configuration
# Uncomment and configure for remote state management

# terraform {
#   backend "s3" {
#     bucket         = "devsecops-lab-terraform-state"
#     key            = "state/terraform.tfstate"
#     region         = "us-east-1"
#     encrypt        = true
#     dynamodb_table = "terraform-state-lock"
#   }
# }

# For local development, state is stored locally
# In production, always use remote state with locking
