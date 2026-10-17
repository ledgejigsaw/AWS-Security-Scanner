resource "aws_s3_bucket" "public_data" {
  bucket = "benchmark-public-data"
  public = true
}
