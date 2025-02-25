#!/usr/bin/env python3
import os
import sys
import subprocess
import re
import requests
import boto3
from botocore.exceptions import ClientError
import getpass
import base64
import json
import time

# --------------------------
# GitHub Functions
# --------------------------

def get_git_remote_url():
    """Get the remote URL from the git config (expects remote named 'origin')."""
    try:
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            capture_output=True, text=True, check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        print("Couldn't get the git remote URL. Make sure you're in the repo directory and 'origin' exists.")
        sys.exit(1)

def parse_github_repo(url):
    """Parse the GitHub repo owner and name from a git URL."""
    ssh_pattern = r"git@github\.com:(?P<owner>[^/]+)/(?P<repo>[^/]+)(\.git)?"
    https_pattern = r"https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)(\.git)?"
    
    match = re.match(ssh_pattern, url) or re.match(https_pattern, url)
    if match:
        owner = match.group("owner")
        repo = match.group("repo").replace(".git", "")
        return owner, repo
    else:
        print("Could not parse GitHub repository info from remote URL:", url)
        sys.exit(1)

def check_push_permission(owner, repo, token):
    """Check if the token has push (read/write) permission to the repo."""
    api_url = f"https://api.github.com/repos/{owner}/{repo}"
    headers = {"Authorization": f"token {token}"}
    
    response = requests.get(api_url, headers=headers)
    if response.status_code != 200:
        print("Error accessing repository info. Check if your token is valid and has the required permissions.")
        sys.exit(1)

    data = response.json()
    permissions = data.get("permissions", {})
    if not permissions.get("push", False):
        print("You do NOT have push permission to this repository. Please update your permissions and try again.")
        sys.exit(1)
    else:
        print("✅ Push permission check passed.")

def check_actions_secrets_permission(owner, repo, token):
    """Check if the token can access actions secrets for the repo."""
    api_url = f"https://api.github.com/repos/{owner}/{repo}/actions/secrets"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "GitHub-API-Check"
    }
    
    response = requests.get(api_url, headers=headers)
    if response.status_code != 200:
        print("❌ You do NOT have access to actions secrets for this repository. Please update your permissions and try again.")
        sys.exit(1)

    data = response.json()
    if "secrets" in data and isinstance(data["secrets"], list):
        print(f"✅ Actions secrets check passed. Found {len(data['secrets'])} secrets.")
    else:
        print("⚠️ No secrets found, but access is confirmed.")

# --------------------------
# AWS Functions
# --------------------------

def get_aws_credentials():
    """
    Get AWS credentials from environment variables or check if they exist in ~/.aws/credentials.
    If not found, prompt the user and persist them to ~/.aws/credentials.
    """
    # Try using credentials from AWS CLI profile (boto3 will automatically load ~/.aws/credentials)
    session = boto3.Session()
    credentials = session.get_credentials()

    if credentials and credentials.access_key and credentials.secret_key:
        print("\n✅ AWS credentials found in ~/.aws/credentials")
        return credentials.access_key, credentials.secret_key, session.region_name or "us-west-2"

    # If credentials aren't found, prompt the user
    print("\n🔍 No AWS credentials found. Please enter them manually.")
    access_key = input("AWS Access Key ID: ").strip()
    secret_key = getpass.getpass("AWS Secret Access Key: ").strip()
    region = input("AWS Region (default: us-west-2): ").strip() or "us-west-2"

    # Persist credentials to ~/.aws/credentials and ~/.aws/config
    save_aws_credentials(access_key, secret_key, region)
    return access_key, secret_key, region

def save_aws_credentials(access_key, secret_key, region):
    """
    Save AWS credentials to ~/.aws/credentials so they persist across sessions.
    """
    aws_credentials_path = os.path.expanduser("~/.aws/credentials")
    aws_config_path = os.path.expanduser("~/.aws/config")

    # Ensure AWS credentials directory exists
    os.makedirs(os.path.dirname(aws_credentials_path), exist_ok=True)

    # Write credentials to ~/.aws/credentials
    with open(aws_credentials_path, "w") as cred_file:
        cred_file.write(f"[default]\n")
        cred_file.write(f"aws_access_key_id = {access_key}\n")
        cred_file.write(f"aws_secret_access_key = {secret_key}\n")

    # Write region to ~/.aws/config
    with open(aws_config_path, "w") as config_file:
        config_file.write(f"[default]\n")
        config_file.write(f"region = {region}\n")

    print(f"\n✅ AWS credentials saved to {aws_credentials_path}")
    print(f"✅ AWS region saved to {aws_config_path}")
    print("🔄 You can now run AWS CLI commands without re-entering credentials.")

def check_aws_permissions(access_key, secret_key, region):
    """Check basic AWS permissions for IAM and S3 (requires read/write permissions)."""
    print("\n🔍 Checking AWS IAM permissions...")
    try:
        iam_client = boto3.client('iam', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
        iam_client.list_roles(MaxItems=1)
        print("✅ IAM permissions check passed (read access confirmed).")
    except ClientError as e:
        print("❌ Error accessing IAM. Make sure your AWS credentials have read/write permissions for IAM.")
        print(e)
        sys.exit(1)

    print("\n🔍 Checking AWS S3 permissions...")
    try:
        s3_client = boto3.client('s3', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
        s3_client.list_buckets()
        print("✅ S3 permissions check passed (read access confirmed).")
    except ClientError as e:
        print("❌ Error accessing S3. Make sure your AWS credentials have read/write permissions for S3.")
        print(e)
        sys.exit(1)

    print("\n✅ Basic AWS permissions for IAM and S3 confirmed!")

# --------------------------
# RESOURCELY_API_TOKEN Functions
# --------------------------

def get_resourcely_api_token():
    """Get RESOURCELY_API_TOKEN from environment or prompt the user and set it in the environment."""
    token = os.getenv("RESOURCELY_API_TOKEN")
    if not token:
        print("\n🔍 No RESOURCELY_API_TOKEN found in the environment. Go to https://portal.resourcely.io Settings > Generate API token and set it with:")
        print("export RESOURCELY_API_TOKEN=<token>")
        sys.exit(1)
    return token

def decode_jwt_payload(token):
    """Decode the payload of a JWT token without verifying the signature."""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid JWT token format")
        payload_b64 = parts[1]
        # Add missing padding if necessary
        missing_padding = len(payload_b64) % 4
        if missing_padding:
            payload_b64 += '=' * (4 - missing_padding)
        payload_json = base64.urlsafe_b64decode(payload_b64).decode('utf-8')
        return json.loads(payload_json)
    except Exception as e:
        raise ValueError(f"Error decoding JWT payload: {e}")

def check_resourcely_api_token(token):
    """Check that the RESOURCELY_API_TOKEN contains admin rights based on its payload."""
    try:
        payload = decode_jwt_payload(token)
        roles = payload.get("@resourcely/roles", [])
        if "admin" not in roles:
            print("❌ RESOURCELY_API_TOKEN does not have admin role. Please use a token with admin privileges.")
            sys.exit(1)
        else:
            print("✅ RESOURCELY_API_TOKEN admin check passed (JWT payload).")
    except Exception as e:
        print("❌ Error decoding RESOURCELY_API_TOKEN:", e)
        sys.exit(1)

def verify_resourcely_api_token(token):
    """
    Verify the RESOURCELY_API_TOKEN by calling the /users/current-user endpoint.
    Checks that the status is 200 and that the returned JSON contains an admin role.
    """
    url = "https://api.dev.resourcely.io/api/v1/users/current-user"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            print(f"❌ RESOURCELY_API_TOKEN validation failed: received status code {response.status_code}")
            sys.exit(1)
        user_data = response.json()
        roles = user_data.get("roles", [])
        if "admin" not in roles:
            print("❌ RESOURCELY_API_TOKEN validation failed: admin role not present in the user data.")
            sys.exit(1)
        else:
            print("✅ RESOURCELY_API_TOKEN external validation passed. Admin role confirmed.")
    except Exception as e:
        print("❌ Error validating RESOURCELY_API_TOKEN with API:", e)
        sys.exit(1)

# --------------------------
# OIDC and IAM Role Functions
# --------------------------

def create_oidc_provider(iam_client):
    """
    Create the GitHub Actions OIDC provider in IAM if it doesn't already exist.
    Idempotently checks for a provider with URL "https://token.actions.githubusercontent.com".
    Returns the provider ARN.
    """
    target_url = "https://token.actions.githubusercontent.com"
    # Normalize target URL by stripping "https://"
    normalized_target_url = target_url.replace("https://", "")
    target_client_ids = ["sts.amazonaws.com"]
    thumbprint = "6938fd4d98bab03faadb97b34396831e3780aea1"
    
    # List existing OIDC providers
    providers = iam_client.list_open_id_connect_providers().get("OpenIDConnectProviderList", [])
    for provider in providers:
        provider_arn = provider["Arn"]
        try:
            details = iam_client.get_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn)
            # Normalize the provider URL
            provider_url = details.get("Url", "")
            normalized_provider_url = provider_url.replace("https://", "")
            if normalized_provider_url == normalized_target_url:
                print(f"✅ OIDC provider already exists: {provider_arn}")
                return provider_arn
        except ClientError as e:
            print("Error retrieving OIDC provider details:", e)
            continue

    # Provider not found; attempt to create it
    try:
        response = iam_client.create_open_id_connect_provider(
            Url=target_url,
            ClientIDList=target_client_ids,
            ThumbprintList=[thumbprint]
        )
        provider_arn = response["OpenIDConnectProviderArn"]
        print(f"✅ Created OIDC provider: {provider_arn}")
        # Wait a few seconds for eventual consistency
        time.sleep(5)
        return provider_arn
    except ClientError as e:
        if e.response['Error']['Code'] == 'EntityAlreadyExists':
            print("✅ OIDC provider already exists (caught error), retrieving existing provider...")
            # Retrieve and return the existing provider ARN
            providers = iam_client.list_open_id_connect_providers().get("OpenIDConnectProviderList", [])
            for provider in providers:
                provider_arn = provider["Arn"]
                try:
                    details = iam_client.get_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn)
                    provider_url = details.get("Url", "")
                    normalized_provider_url = provider_url.replace("https://", "")
                    if normalized_provider_url == normalized_target_url:
                        return provider_arn
                except ClientError:
                    continue
            print("❌ OIDC provider exists but could not be retrieved.")
            sys.exit(1)
        else:
            print("❌ Failed to create OIDC provider:", e)
            sys.exit(1)



def create_oidc_role(iam_client, provider_arn, repository):
    """
    Create the IAM role 'GithubActionsOIDC' with a trust policy allowing GitHub Actions OIDC if it doesn't exist.
    Idempotently checks for the role, and waits until it is fully created.
    """
    role_name = "ResourcelyGithubActionsOIDC"
    # Define the trust policy referencing the OIDC provider
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Federated": provider_arn
                },
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringLike": {
                        "token.actions.githubusercontent.com:sub": [f"repo:{repository}:*"],
                        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
                    }
                }
            }
        ]
    }
    try:
        # Check if the role already exists
        iam_client.get_role(RoleName=role_name)
        print(f"✅ IAM role '{role_name}' already exists.")
    except iam_client.exceptions.NoSuchEntityException:
        # Role does not exist; create it
        try:
            iam_client.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Description="Role for GitHub Actions OIDC"
            )
            print(f"✅ Creating IAM role '{role_name}'...")
            # Wait until the role exists (polling)
            for _ in range(10):
                try:
                    iam_client.get_role(RoleName=role_name)
                    print(f"✅ IAM role '{role_name}' is now available.")
                    break
                except iam_client.exceptions.NoSuchEntityException:
                    time.sleep(3)
            else:
                print(f"❌ Timeout waiting for IAM role '{role_name}' to become available.")
                sys.exit(1)
        except ClientError as e:
            print("❌ Failed to create IAM role:", e)
            sys.exit(1)
    return role_name

def patch_workflow_file(new_role_arn, workflow_file=".github/workflows/plan_and_apply.yml"):
    """
    Patch the workflow file in place, replacing the role-to-assume values with the new role ARN.
    """
    try:
        with open(workflow_file, "r") as f:
            content = f.read()
        new_content = re.sub(r"(role-to-assume:\s*)(\S+)", r"\1" + new_role_arn, content)
        with open(workflow_file, "w") as f:
            f.write(new_content)
        print(f"✅ Updated {workflow_file} with new role-to-assume: {new_role_arn}")
    except Exception as e:
        print("❌ Failed to patch the workflow file:", e)
        sys.exit(1)

# --------------------------
# Main Function
# --------------------------

def main():
    # GitHub Checks
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("❌ Please set your GITHUB_TOKEN environment variable with the 'workflow' and 'read:org' permissions.")
        sys.exit(1)
    
    remote_url = get_git_remote_url()
    owner, repo = parse_github_repo(remote_url)
    print(f"🔍 Repository detected: {owner}/{repo}")
    
    check_push_permission(owner, repo, token)
    check_actions_secrets_permission(owner, repo, token)
    
    print("\n✅ GitHub checks passed! Now collecting AWS credentials...\n")
    # AWS Checks
    access_key, secret_key, region = get_aws_credentials()
    check_aws_permissions(access_key, secret_key, region)
    
    print("\n✅ AWS checks passed! Now checking RESOURCELY_API_TOKEN...\n")
    # RESOURCELY_API_TOKEN Checks
    resourcely_token = get_resourcely_api_token()
    check_resourcely_api_token(resourcely_token)
    verify_resourcely_api_token(resourcely_token)
    
    print("\n✅ All basic checks passed! Now creating IAM role for GitHub Actions OIDC...\n")
    # Onboarding Step: Create OIDC provider and IAM role for GitHub Actions
    iam_client = boto3.client('iam', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    provider_arn = create_oidc_provider(iam_client)
    repository = f"{owner}/{repo}"
    role_name = create_oidc_role(iam_client, provider_arn, repository)

    # Retrieve the full role ARN
    try:
        role_response = iam_client.get_role(RoleName=role_name)
        new_role_arn = role_response["Role"]["Arn"]
    except ClientError as e:
        print("❌ Failed to retrieve role ARN:", e)
        sys.exit(1)
    
    # Patch the workflow file with the new role ARN
    patch_workflow_file(new_role_arn)
    
    print("\n🚀 Onboarding complete! Continuing with further onboarding steps...\n")

if __name__ == "__main__":
    main()
