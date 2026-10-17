resource "aws_s3_bucket" "public_data" {
  bucket = "benchmark-public-data"
  public = true
  encryption = true
  versioning = true
  block_public_access = true
  logging = true
}
