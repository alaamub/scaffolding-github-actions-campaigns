# main.tf

resource "aws_s3_bucket" "resourcely-campaigns-test-bucket_aannxfsuzheykxhtMshbmm94dxCHA" {
  bucket = "resourcely-campaigns-test-bucketaannxfsuzheykxht"

   lifecycle {
    prevent_destroy = true
  }

}

resource "aws_s3_bucket_public_access_block" "resourcely-campaigns-test-bucket_aannxfsuzheykxhtMshbmm94dxCHA" {
  bucket                  = aws_s3_bucket.resourcely-campaigns-test-bucket_aannxfsuzheykxhtMshbmm94dxCHA.id
  block_public_acls       = false
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = false
}

resource "aws_s3_bucket_ownership_controls" "resourcely-campaigns-test-bucket_aannxfsuzheykxhtMshbmm94dxCHA" {
  bucket = aws_s3_bucket.resourcely-campaigns-test-bucket_aannxfsuzheykxhtMshbmm94dxCHA.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "resourcely-campaigns-test-bucket_aannxfsuzheykxhtMshbmm94dxCHA" {
  bucket = aws_s3_bucket.resourcely-campaigns-test-bucket_aannxfsuzheykxhtMshbmm94dxCHA.id

  versioning_configuration {
    status = "Enabled"
  }
}
