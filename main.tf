# main.tf

resource "aws_s3_bucket" "campaigns-resource_ckaMshbmm94dxCHA" {
  bucket = "campaigns-resource-test-bucket-ranrpmubjeedkqlk"
}

resource "aws_s3_bucket_public_access_block" "campaigns-resource_ckaMshbmm94dxCHA" {
  bucket                  = aws_s3_bucket.campaigns-resource_ckaMshbmm94dxCHA.id
  block_public_acls       = false
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = false
}

resource "aws_s3_bucket_ownership_controls" "campaigns-resource_ckaMshbmm94dxCHA" {
  bucket = aws_s3_bucket.campaigns-resource_ckaMshbmm94dxCHA.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "campaigns-resource_ckaMshbmm94dxCHA" {
  bucket = aws_s3_bucket.campaigns-resource_ckaMshbmm94dxCHA.id

  versioning_configuration {
    status = "Enabled"
  }
}
