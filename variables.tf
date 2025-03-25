variable "aws_region" {
  description = "AWS region to deploy resources"
  default     = "us-east-1"
}

variable "github_repo" {
  description = "GitHub repository name (username/repo)"
  type        = string
}

variable "github_branch" {
  description = "GitHub branch to watch"
  default     = "main"
}

variable "github_token" {
  description = "GitHub OAuth token for webhook creation"
  type        = string
  sensitive   = true
}

variable "app_name" {
  description = "Application name used for resource naming"
  default     = "flask-demo"
}
