output "bucket_name" {
  value       = aws_s3_bucket.media.bucket
  description = "S3 media bucket"
}

output "cloudfront_distribution_id" {
  value       = aws_cloudfront_distribution.cdn.id
  description = "CloudFront distribution ID"
}

output "cloudfront_domain_name" {
  value       = aws_cloudfront_distribution.cdn.domain_name
  description = "CloudFront domain"
}
