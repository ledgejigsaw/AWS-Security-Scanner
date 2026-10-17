variable "security_group_name" {
  type = string
}

resource "aws_security_group" "unknown" {
  name = var.security_group_name
  description = "Name is intentionally unresolved."
}
