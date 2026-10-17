variable "bucket_name" {
  type = string
}

resource "aws_s3_bucket" "data" {
  bucket = var.bucket_name
  public = false
  encryption = true
  versioning = true
  block_public_access = true
  logging = true
  bucket_policy = {
    Statement = [{
      Effect = "Deny"
      Principal = "*"
      Action = "s3:*"
      Resource = ["arn:aws:s3:::benchmark-bucket", "arn:aws:s3:::benchmark-bucket/*"]
      Condition = {
        Bool = {
          "aws:SecureTransport" = "false"
        }
      }
    }]
  }
}
