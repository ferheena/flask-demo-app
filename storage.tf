# S3 bucket for CodePipeline artifacts
resource "aws_s3_bucket" "artifact_bucket" {
  bucket_prefix = "${var.app_name}-artifacts-1-"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "block_public_access" {
  bucket = aws_s3_bucket.artifact_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
