variable "bucket_name" {
  type = string
}

resource "aws_s3_bucket" "data" {
  bucket = var.bucket_name
}
