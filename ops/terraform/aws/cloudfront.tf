resource "aws_cloudfront_origin_access_control" "oac" {
  name                              = "${var.project}-oac"
  description                       = "OAC for private S3 media bucket"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_s3_bucket" "cf_logs" {
  bucket = "${var.project}-cf-logs-${var.aws_region}"
  force_destroy = true
  tags   = local.tags
}

resource "aws_cloudfront_response_headers_policy" "cors" {
  name = "${var.project}-cors"
  cors_config {
    access_control_allow_credentials = false
    access_control_allow_headers     = ["*"]
    access_control_allow_methods     = ["GET", "HEAD"]
    access_control_allow_origins     = ["*"]
    access_control_expose_headers    = ["Content-Length", "Content-Type"]
    origin_override                  = true
  }
}

resource "aws_cloudfront_distribution" "cdn" {
  enabled             = true
  price_class         = var.cf_price_class
  wait_for_deployment = false

  origin {
    domain_name              = aws_s3_bucket.media.bucket_regional_domain_name
    origin_id                = "media-s3"
    origin_access_control_id = aws_cloudfront_origin_access_control.oac.id
  }

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "media-s3"
    viewer_protocol_policy = "redirect-to-https"
    compress = true
    forwarded_values {
      query_string = true
      cookies { forward = "none" }
    }
    min_ttl                = 0
    default_ttl            = 86400
    max_ttl                = 31536000
  }

  ordered_cache_behavior {
    path_pattern           = "/hls/*"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "media-s3"
    viewer_protocol_policy = "redirect-to-https"
    compress               = true
    forwarded_values { query_string = true cookies { forward = "none" } }
    min_ttl   = 0
    default_ttl = 3600
    max_ttl   = 86400
  }

  ordered_cache_behavior {
    path_pattern           = "/downloads/*"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "media-s3"
    viewer_protocol_policy = "redirect-to-https"
    compress               = true
    forwarded_values { query_string = true cookies { forward = "none" } }
    min_ttl   = 0
    default_ttl = 600
    max_ttl   = 3600
  }

  ordered_cache_behavior {
    path_pattern           = "/bundles/*"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "media-s3"
    viewer_protocol_policy = "redirect-to-https"
    compress               = true
    forwarded_values { query_string = true cookies { forward = "none" } }
    min_ttl   = 0
    default_ttl = 600
    max_ttl   = 3600
  }

  ordered_cache_behavior {
    path_pattern           = "/artwork/*"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "media-s3"
    viewer_protocol_policy = "redirect-to-https"
    response_headers_policy_id = aws_cloudfront_response_headers_policy.cors.id
    compress               = true
    forwarded_values { query_string = false cookies { forward = "none" } }
    min_ttl   = 0
    default_ttl = 86400
    max_ttl   = 31536000
  }

  ordered_cache_behavior {
    path_pattern           = "/subs/*"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "media-s3"
    viewer_protocol_policy = "redirect-to-https"
    response_headers_policy_id = aws_cloudfront_response_headers_policy.cors.id
    compress               = true
    forwarded_values { query_string = false cookies { forward = "none" } }
    min_ttl   = 0
    default_ttl = 86400
    max_ttl   = 31536000
  }

  restrictions {
    geo_restriction { restriction_type = "none" }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  logging_config {
    bucket = aws_s3_bucket.cf_logs.bucket_domain_name
    include_cookies = false
    prefix = "cf_logs/"
  }

  tags = local.tags
}

# Allow CloudFront OAC to GetObject from the bucket
data "aws_caller_identity" "current" {}

resource "aws_s3_bucket_policy" "media_oac" {
  bucket = aws_s3_bucket.media.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowCloudFrontOAC"
        Effect   = "Allow"
        Principal = { Service = "cloudfront.amazonaws.com" }
        Action   = ["s3:GetObject"]
        Resource = ["${aws_s3_bucket.media.arn}/*"]
        Condition = {
          StringEquals = { "AWS:SourceArn" = aws_cloudfront_distribution.cdn.arn }
        }
      }
    ]
  })
}
