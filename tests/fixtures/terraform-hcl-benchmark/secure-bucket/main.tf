resource "aws_s3_bucket" "private_data" {
  bucket = "benchmark-private-data"
  public = false
  encryption = true
  versioning = true
  block_public_access = true
  logging = true
}
