resource "aws_kms_key" "portal_token_signing" {
  description              = "Portal session token signing"
  customer_master_key_spec = "RSA_2048"
  key_usage                = "SIGN_VERIFY"
}

resource "aws_kms_key" "portal_pq_pilot" {
  description = "ML-DSA pilot for document signing"
  key_spec    = "ML_DSA_65"
  key_usage   = "SIGN_VERIFY"
}

resource "aws_acm_certificate" "portal" {
  domain_name   = "portal.tejomaya.example"
  key_algorithm = "EC_prime256v1"
}

resource "aws_lb_listener" "portal_https" {
  port       = 443
  protocol   = "HTTPS"
  ssl_policy = "ELBSecurityPolicy-2016-08"
}
