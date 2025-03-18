terraform {
  backend "s3" {
    bucket   = "resourcely-campaigns-terraform-state-315040492946-us-west-2"
    region   = "us-west-2"
    key      = "terraform.tfstate"
  }
}
