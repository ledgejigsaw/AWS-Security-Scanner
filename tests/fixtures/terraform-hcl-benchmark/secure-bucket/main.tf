resource "aws_security_group" "safe" {
  name = "benchmark-private-security-group"
  description = "No inbound rules are configured."
}
