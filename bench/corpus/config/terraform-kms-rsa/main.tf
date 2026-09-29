resource "aws_kms_key" "signing" {
  description              = "token signing"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "RSA_2048"
}
