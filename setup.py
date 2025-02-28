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
from nacl import encoding, public

CRED_DIR = os.path.expanduser("~/.resourcely")
CRED_FILE = os.path.join(CRED_DIR, "credential")

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
            print(f"❌ RESOURCELY_API_TOKEN validation failed: received status code {response.status_code}. Make sure you set a fresh RESOURCELY_API_TOKEN as environment variable")
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
# S3 Bucket Functions
# --------------------------
def get_account_id(sts_client):
    """
    Retrieve the AWS account ID from the current credentials.
    """
    try:
        identity = sts_client.get_caller_identity()
        return identity["Account"]
    except ClientError as e:
        print("❌ Failed to retrieve AWS account ID:", e)
        sys.exit(1)
        
def create_s3_bucket(s3_client, sts_client, base_bucket_name="resourcely-campaigns-terraform-state", region="us-west-2"):
    """
    Create the S3 bucket for Terraform state if it doesn't exist.
    Generates a unique bucket name using the AWS account ID and region.
    Ensures the bucket has public access blocked and waits until it's created.
    Returns the bucket name.
    """
    account_id = get_account_id(sts_client)
    # Generate a bucket name that is unique per account and region
    bucket_name = f"{base_bucket_name}-{account_id}-{region}"
    try:
        s3_client.head_bucket(Bucket=bucket_name)
        print(f"✅ S3 bucket '{bucket_name}' already exists.")
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code in ["404", "NoSuchBucket"]:
            print(f"ℹ️ S3 bucket '{bucket_name}' does not exist, creating it...")
            create_bucket_kwargs = {'Bucket': bucket_name}
            # if region != "us-west-2":
            create_bucket_kwargs['CreateBucketConfiguration'] = {'LocationConstraint': region}
            try:
                s3_client.create_bucket(**create_bucket_kwargs)
                waiter = s3_client.get_waiter('bucket_exists')
                waiter.wait(Bucket=bucket_name)
                print(f"✅ S3 bucket '{bucket_name}' created.")
            except ClientError as e:
                print(f"❌ Failed to create S3 bucket '{bucket_name}':", e)
                sys.exit(1)
        else:
            print(f"❌ Error checking S3 bucket '{bucket_name}':", e)
            sys.exit(1)
    # Apply public access block
    try:
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        print(f"✅ Public access blocked for bucket '{bucket_name}'.")
    except ClientError as e:
        print(f"❌ Failed to set public access block for bucket '{bucket_name}':", e)
        sys.exit(1)
    # bucket_arn = f"arn:aws:s3:::{bucket_name}"
    return bucket_name

def patch_terraform_file(new_bucket_value, terraform_file="terraform.tf"):
    """
    Patch the terraform.tf file, replacing the bucket value with the new bucket value.
    """
    try:
        with open(terraform_file, "r") as f:
            content = f.read()
        new_content = re.sub(r'(bucket\s*=\s*")[^"]+(")', r'\1' + new_bucket_value + r'\2', content)
        with open(terraform_file, "w") as f:
            f.write(new_content)
        print(f"✅ Updated {terraform_file} with new bucket: {new_bucket_value}")
    except Exception as e:
        print("❌ Failed to patch the terraform file:", e)
        sys.exit(1)

# --------------------------
# S3 Bucket Permissions 
# --------------------------
def get_current_aws_principal(sts_client):
    """
    Retrieves the AWS ARN of the currently authenticated IAM user or role.
    """
    try:
        identity = sts_client.get_caller_identity()
        return identity.get("Arn")
    except ClientError as e:
        print("❌ Failed to retrieve AWS principal ARN:", e)
        sys.exit(1)

def apply_bucket_policy(s3_client, sts_client, bucket_name):
    """
    Idempotently applies a bucket policy to allow access to the bucket from the current AWS principal.
    
    It grants s3:GetObject, s3:PutObject, and s3:ListBucket permissions.
    If a statement with Sid "AllowLocalDockerAccess" exists and already matches, nothing is changed.
    Otherwise, the policy is updated (or created).
    """
    principal_arn = get_current_aws_principal(sts_client)
    intended_statement = {
        "Sid": "AllowLocalDockerAccess",
        "Effect": "Allow",
        "Principal": {"AWS": principal_arn},
        "Action": [
            "s3:GetObject",
            "s3:PutObject",
            "s3:ListBucket"
        ],
        "Resource": [
            f"arn:aws:s3:::{bucket_name}",
            f"arn:aws:s3:::{bucket_name}/*"
        ]
    }
    
    # Try to retrieve the current bucket policy.
    try:
        response = s3_client.get_bucket_policy(Bucket=bucket_name)
        current_policy = json.loads(response['Policy'])
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
            current_policy = {"Version": "2012-10-17", "Statement": []}
        else:
            print("❌ Failed to retrieve bucket policy:", e)
            sys.exit(1)
    
    # Look for an existing statement with Sid "AllowLocalDockerAccess"
    statement_found = False
    for stmt in current_policy["Statement"]:
        if stmt.get("Sid") == "AllowLocalDockerAccess":
            statement_found = True
            # If it exactly matches our intended statement, do nothing.
            if stmt == intended_statement:
                print(f"✅ Bucket policy for local Docker access already applied for bucket '{bucket_name}'.")
                return
            else:
                # Update the existing statement.
                stmt.update(intended_statement)
                break
    if not statement_found:
        # Append the intended statement.
        current_policy["Statement"].append(intended_statement)
    
    # Apply the updated (or new) policy.
    policy_json = json.dumps(current_policy)
    try:
        s3_client.put_bucket_policy(Bucket=bucket_name, Policy=policy_json)
        print(f"✅ Bucket policy updated for bucket '{bucket_name}' to allow access from principal {principal_arn}.")
    except ClientError as e:
        print("❌ Failed to update bucket policy:", e)
        sys.exit(1)

def attach_s3_policy_to_role(iam_client, role_name, bucket_name):
    """
    Attaches an inline policy to the specified IAM role to allow access to the given S3 bucket for Terraform state.
    Grants s3:ListBucket on the bucket and s3:GetObject, s3:PutObject, s3:DeleteObject on its objects.
    This operation is idempotent; running it repeatedly will update the policy.
    """
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
        {
            "Sid": "AllowS3ListBucket",
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::resourcely-campaigns*"
        },
        {
            "Sid": "AllowS3ObjectAccess",
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject"
            ],
            "Resource": "arn:aws:s3:::resourcely-campaigns*/*"
        },
        {
            "Sid": "AllowFullS3BucketManagementForCampaigns",
            "Effect": "Allow",
            "Action": "s3:*",
            "Resource": "*"
            },
        {
            "Sid": "AllowS3GetBucketPolicy",
            "Effect": "Allow",
            "Action": "s3:GetBucketPolicy",
            "Resource": "arn:aws:s3:::resourcely-campaigns*"
        }
        ]
    }
    policy_name = "TerraformStateS3AccessPolicy"
    try:
        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy_document)
        )
        print(f"✅ Attached S3 policy '{policy_name}' to role '{role_name}'.")
    except ClientError as e:
        print("❌ Failed to attach S3 policy to role:", e)
        sys.exit(1)

# --------------------------
# Patch .resourcely.yaml
# --------------------------
def patch_resourcely_yaml(new_bucket, filename=".resourcely.yaml"):
    """
    Patch the .resourcely.yaml file to update the S3 bucket location in the state_file_config.
    Replaces the current bucket in the URL with the new_bucket value.
    """
    try:
        with open(filename, "r") as f:
            content = f.read()
        # Build the new S3 path
        new_path = f"s3://{new_bucket}/terraform.tfstate"
        # Use regex to find and replace the S3 URL.
        # This pattern matches any string like s3://<anything>/terraform.tfstate
        new_content = re.sub(r"s3://[^/]+/terraform\.tfstate", new_path, content)
        with open(filename, "w") as f:
            f.write(new_content)
        print(f"✅ Updated {filename} with new S3 bucket path: {new_path}")
    except Exception as e:
        print("❌ Failed to patch .resourcely.yaml:", e)
        sys.exit(1)

# --------------------------
# Add RESOURCELY_API_TOKEN to Github Actions 
# --------------------------
def encrypt_secret(public_key: str, secret_value: str) -> str:
    """
    Encrypts a secret using the provided public key from GitHub.
    """
    public_key_obj = public.PublicKey(public_key.encode("utf-8"), encoding.Base64Encoder())
    sealed_box = public.SealedBox(public_key_obj)
    encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
    return encoding.Base64Encoder().encode(encrypted).decode("utf-8")

def update_github_secret(owner, repo, github_token, secret_name, secret_value):
    """
    Retrieves the public key for the repository, encrypts the secret value,
    and then creates/updates the secret in the repository via the GitHub API.
    """
    # Retrieve the public key
    url = f"https://api.github.com/repos/{owner}/{repo}/actions/secrets/public-key"
    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github+json"
    }
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        print("❌ Failed to retrieve public key for repository secrets:", response.json())
        sys.exit(1)
    public_key_data = response.json()
    public_key = public_key_data["key"]
    key_id = public_key_data["key_id"]

    # Encrypt the secret using the public key
    encrypted_value = encrypt_secret(public_key, secret_value)

    # Create or update the secret using PUT
    put_url = f"https://api.github.com/repos/{owner}/{repo}/actions/secrets/{secret_name}"
    payload = {
        "encrypted_value": encrypted_value,
        "key_id": key_id
    }
    put_response = requests.put(put_url, headers=headers, json=payload)
    if put_response.status_code in [201, 204]:
        print(f"✅ Secret '{secret_name}' updated successfully.")
    else:
        print("❌ Failed to update secret:", put_response.json())
        sys.exit(1)

# --------------------------
# Commit changes to the repo and enable workflows
# --------------------------
def git_commit_and_push():
    """
    Check for any changes, commit them, and push to the main branch.
    """
    try:
        # Check for any changed files
        status = subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True)
        if status.stdout.strip():
            print("ℹ️ Changes detected. Committing and pushing...")
            subprocess.run(["git", "add", "."], check=True)
            subprocess.run(["git", "commit", "-m", "Automated onboarding updates"], check=True)
            subprocess.run(["git", "push", "origin", "main"], check=True)
            print("✅ Changes committed and pushed to main.")
        else:
            print("ℹ️ No changes to commit.")
    except subprocess.CalledProcessError as e:
        print("❌ Git commit/push failed:", e)
        sys.exit(1)

def enable_workflows(owner, repo, github_token):
    """
    Enable all workflows for the repository using the GitHub API.
    For each workflow, if its state is not 'active', send a PUT request to enable it.
    """
    workflows_url = f"https://api.github.com/repos/{owner}/{repo}/actions/workflows"
    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github.v3+json"
    }
    response = requests.get(workflows_url, headers=headers)
    if response.status_code != 200:
        print("❌ Failed to retrieve workflows:", response.json())
        sys.exit(1)
    workflows = response.json().get("workflows", [])
    if not workflows:
        print("ℹ️ No workflows found in the repository.")
    for workflow in workflows:
        # If the workflow state is not active (i.e. disabled), enable it.
        if workflow.get("state") != "active":
            workflow_id = workflow.get("id")
            enable_url = f"https://api.github.com/repos/{owner}/{repo}/actions/workflows/{workflow_id}/enable"
            enable_response = requests.put(enable_url, headers=headers)
            if enable_response.status_code == 204:
                print(f"✅ Enabled workflow '{workflow.get('name')}' (ID: {workflow_id}).")
            else:
                print(f"❌ Failed to enable workflow '{workflow.get('name')}':", enable_response.json())
                print(f"❌ You can enable Workflows manually by navigating to this repo URL https://github.com/{owner}/{repo}/actions")
                sys.exit(1)
        else:
            print(f"✅ Workflow '{workflow.get('name')}' is already enabled.")

# --------------------------
# Check if plan workflows work
# --------------------------
def update_main_tf_directly(new_versioning_status="Enabled"):
    """
    Update main.tf to set the versioning_configuration status.
    Replace:
      versioning_configuration {
        status = "Disabled"
      }
    with:
      versioning_configuration {
        status = "Enabled"
      }
    This function is idempotent; if the file already has the desired value, no change is made.
    """
    try:
        with open("main.tf", "r") as f:
            content = f.read()
        # Replace the versioning configuration block from "Disabled" to new_versioning_status.
        new_content, count = re.subn(
            r'(versioning_configuration\s*{\s*status\s*=\s*")Disabled(")',
            r'\1' + new_versioning_status + r'\2',
            content
        )
        if count > 0:
            with open("main.tf", "w") as f:
                f.write(new_content)
            print(f"✅ Updated main.tf: set versioning_configuration status = {new_versioning_status}")
        else:
            print("ℹ️ main.tf already has the desired versioning status; no update needed.")
    except Exception as e:
        print("❌ Failed to update main.tf:", e)
        sys.exit(1)

def update_main_and_push():
    """
    Check for any changes in main.tf, commit them, and push directly to main.
    """
    try:
        status = subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True)
        if status.stdout.strip():
            print("ℹ️ Changes detected on main. Committing and pushing...")
            subprocess.run(["git", "add", "."], check=True)
            subprocess.run(["git", "commit", "-m", "Update versioning_configuration status in main.tf"], check=True)
            subprocess.run(["git", "push", "origin", "main"], check=True)
            print("✅ Changes committed and pushed to main.")
        else:
            print("ℹ️ No changes to commit on main.")
    except subprocess.CalledProcessError as e:
        print("❌ Git commit/push failed:", e)
        sys.exit(1)
    # Retrieve the commit SHA after pushing.
    commit_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    return commit_sha

def wait_for_plan_job_success(owner, repo, commit_sha, github_token, timeout=600, poll_interval=30):
    """
    Poll the GitHub Actions API for the workflow run on the given branch that matches the commit_sha.
    Then, check the "Plan Sandbox" job in that run and wait until that job completes successfully.
    """
    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github+json"
    }
    runs_url = f"https://api.github.com/repos/{owner}/{repo}/actions/runs"
    start_time = time.time()
    print(f"ℹ️ Waiting for 'Plan Sandbox' job for commit {commit_sha}...")
    while time.time() - start_time < timeout:
        # Get workflow runs, then filter by head_sha
        params = {"head_sha": commit_sha, "event": "push"}
        response = requests.get(runs_url, headers=headers, params=params)
        if response.status_code != 200:
            print("❌ Failed to retrieve workflow runs:", response.json())
            sys.exit(1)
        runs = response.json().get("workflow_runs", [])
        if runs:
            # Assuming the most recent run is the one for our commit
            latest_run = runs[0]
            run_id = latest_run.get("id")
            # Now get the jobs for this run
            jobs_url = f"https://api.github.com/repos/{owner}/{repo}/actions/runs/{run_id}/jobs"
            jobs_response = requests.get(jobs_url, headers=headers)
            if jobs_response.status_code != 200:
                print("❌ Failed to retrieve jobs for workflow run:", jobs_response.json())
                sys.exit(1)
            jobs = jobs_response.json().get("jobs", [])
            for job in jobs:
                if job.get("name") == "plan_and_apply / plan-and-apply-app-dev-us-west-2 / Plan Sandbox":
                    job_status = job.get("status")
                    job_conclusion = job.get("conclusion")
                    print(f"ℹ️ 'Plan Sandbox' job: status = {job_status}, conclusion = {job_conclusion}")
                    if job_status == "completed" and job_conclusion == "success":
                        print("✅ 'Plan Sandbox' job succeeded for commit", commit_sha)
                        return
                    elif job_status == "completed" and job_conclusion != "success":
                        print(f"❌ 'Plan Sandbox' job failed with conclusion: {job_conclusion}")
                        sys.exit(1)
            print("ℹ️ 'Plan Sandbox' job not found yet for this commit.")
        else:
            print(f"ℹ️ No workflow run found for commit {commit_sha}.")
        time.sleep(poll_interval)
    print("❌ Timeout waiting for 'Plan Sandbox' job to complete successfully for commit", commit_sha)
    sys.exit(1)

# --------------------------
# Check change management setup 
# --------------------------
def check_change_management_setup(resourcely_api_token):
    """
    Check if change management is configured by calling:
      GET https://api.dev.resourcely.io/api/v1/settings/git-servers
    It verifies that at least one git server in the response has a non-empty 
    repo_glob_patterns array. If not, it instructs the user to configure change management.
    """
    url = "https://api.dev.resourcely.io/api/v1/settings/git-servers"
    headers = {
        "Authorization": f"Bearer {resourcely_api_token}",
        "Accept": "application/json"
    }
    try:
        response = requests.get(url, headers=headers)
    except Exception as e:
        print("❌ Error calling change management API:", e)
        sys.exit(1)
    if response.status_code != 200:
        print(f"❌ Failed to retrieve git servers. Status code: {response.status_code}")
        sys.exit(1)
    data = response.json()
    git_servers = data.get("git_servers", [])
    configured = False
    for server in git_servers:
        repo_glob_patterns = server.get("repo_glob_patterns", [])
        if repo_glob_patterns and len(repo_glob_patterns) > 0:
            configured = True
            break
    if configured:
        print("✅ Change management is configured properly.")
    else:
        print("❌ Change management is not configured correctly.")
        print("Please configure change management at:")
        print("https://portal.dev.resourcely.io/settings/change-management")
        print("Then run the script again.")
        sys.exit(1)

# --------------------------
# Polls the diagnostics endpoint to validate .resourcely.yaml
# --------------------------
def poll_yaml_config_diagnostics(api_token, repo_url, max_attempts=5, interval=5):
    """
    Polls the diagnostics endpoint to ensure that the .resourcely.yaml configuration is valid.
    
    It calls GET https://api.dev.resourcely.io/api/v1/diagnostics/yaml-config using the provided
    RESOURCELY_API_TOKEN. It then checks that for repo_url, the "result" is "TF_CONFIG_SCAN_RESULT_VALID_CONFIG"
    and that the "errors" array is empty.
    
    If these conditions are met, it prints a success message and returns.
    Otherwise, it waits 'interval' seconds and retries up to max_attempts times before exiting.
    """
    url = "https://api.dev.resourcely.io/api/v1/diagnostics/yaml-config"
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Accept": "application/json"
    }
    attempt = 0
    while attempt < max_attempts:
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            print(f"❌ Failed to retrieve YAML config diagnostics (status code {response.status_code}): {response.text}")
        else:
            fqdn_repo_url = f"https://github.com/{repo_url}"
            data = response.json()
            repos = data.get("repos", {})
            repo_diag = repos.get(fqdn_repo_url)
            if repo_diag:
                result = repo_diag.get("result")
                errors = repo_diag.get("errors", [])
                if result == "TF_CONFIG_SCAN_RESULT_VALID_CONFIG" and not errors:
                    print("✅ YAML configuration diagnostics are valid for the repository.")
                    return
                else:
                    print(f"ℹ️ Diagnostics for '{repo_url}' not valid yet: result = {result}, errors = {errors}")
            else:
                print(f"ℹ️ Repository '{repo_url}' not found in diagnostics response.")
        attempt += 1
        if attempt < max_attempts:
            print(f"ℹ️ Waiting {interval} seconds before retrying... (attempt {attempt+1}/{max_attempts})")
            time.sleep(interval)
    print("❌ Timeout: YAML configuration diagnostics did not become valid after maximum attempts.")
    sys.exit(1)

# --------------------------
# Polls the diagnostics endpoint to verify github or gitlab installation is successful 
# --------------------------
def poll_diagnostics(api_token, max_attempts=5, interval=5):
    """
    Polls the diagnostics endpoint to confirm that either DIAGNOSTIC_SOURCE_GITLAB or 
    DIAGNOSTIC_SOURCE_GITHUB has all its checks with DIAGNOSTIC_STATUS_SUCCESS.
    
    If found, prints success and returns. Otherwise, it retries up to max_attempts times
    before exiting.
    """
    url = "https://api.dev.resourcely.io/api/v1/diagnostics"
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Accept": "application/json"
    }
    attempt = 0
    while attempt < max_attempts:
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            print(f"❌ Failed to retrieve diagnostics (status code {response.status_code}): {response.text}")
        else:
            data = response.json()
            diagnostics = data.get("diagnostics", [])
            success_found = False
            for diagnostic in diagnostics:
                source = diagnostic.get("source", "")
                if source in ["DIAGNOSTIC_SOURCE_GITLAB", "DIAGNOSTIC_SOURCE_GITHUB"]:
                    checks = diagnostic.get("checks", [])
                    # Verify that all checks for this diagnostic have a status of DIAGNOSTIC_STATUS_SUCCESS
                    if all(check.get("status") == "DIAGNOSTIC_STATUS_SUCCESS" for check in checks):
                        print(f"✅ Diagnostics for source {source} are all successful.")
                        success_found = True
                        break
                    else:
                        print(f"ℹ️ Diagnostics for source {source} are not fully successful yet.")
            if success_found:
                return
        attempt += 1
        if attempt < max_attempts:
            print(f"ℹ️ Retrying diagnostics check in {interval} seconds... (attempt {attempt+1}/{max_attempts})")
            time.sleep(interval)
    print("❌ Timeout: GitHub diagnostics did not reach success status after maximum attempts.")
    sys.exit(1)

# --------------------------
# provisioned ngrok 
# --------------------------
def load_ngrok_credentials():
    """
    Load ngrok credentials from the ~/.resourcely/credential file if it exists.
    Returns a dict if the file exists and contains 'tunnel' with seed and auth_token,
    otherwise returns None.
    """
    if os.path.exists(CRED_FILE):
        try:
            with open(CRED_FILE, "r") as f:
                data = json.load(f)
            tunnel = data.get("tunnel")
            if tunnel and tunnel.get("seed") and tunnel.get("auth_token"):
                print("✅ Ngrok credentials already exist in ~/.resourcely/credential.")
                return data
            else:
                print("ℹ️ Ngrok credential file exists but is missing required fields.")
                return None
        except Exception as e:
            print(f"❌ Error reading credentials file: {e}")
            return None
    else:
        return None

def save_ngrok_credentials(data):
    """
    Save ngrok credentials to ~/.resourcely/credential.
    Creates the directory if needed.
    """
    try:
        os.makedirs(CRED_DIR, exist_ok=True)
        with open(CRED_FILE, "w") as f:
            json.dump(data, f, indent=2)
        print(f"✅ Ngrok credentials saved to {CRED_FILE}")
    except Exception as e:
        print(f"❌ Failed to save credentials file: {e}")
        sys.exit(1)

def ensure_ngrok_setup(resourcely_api_token):
    """
    Check if the ngrok proxy is already provisioned by:
      1. Checking the local credentials file (~/.resourcely/credential).
      2. Calling GET on https://api.dev.resourcely.io/api/v1/infrastructure/campaigns.
         If the tunnel exists, use it; otherwise, call POST to provision.
    Returns the resulting JSON data.
    """
    url = "https://api.dev.resourcely.io/api/v1/infrastructure/campaigns"
    headers = {
        "Authorization": f"Bearer {resourcely_api_token}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    
    # Check if credentials already exist locally.
    local_creds = load_ngrok_credentials()
    if local_creds:
        # We assume that if credentials exist, the ngrok proxy is provisioned.
        return local_creds

    # Otherwise, try to GET the infrastructure information.
    try:
        response = requests.get(url, headers=headers)
    except Exception as e:
        print(f"❌ Exception while retrieving infrastructure campaigns: {e}")
        response = None

    data = None
    if response is not None and response.status_code == 200:
        data = response.json()
    else:
        print("ℹ️ Failed to retrieve infrastructure campaigns or non-200 response received. Proceeding to provision ngrok proxy...")

    tunnel = data.get("tunnel") if data else None

    if tunnel:
        print("✅ Ngrok proxy already provisioned.")
        save_ngrok_credentials(data)
        return data
    else:
        print("ℹ️ Ngrok proxy not found. Attempting to create it...")
        post_response = requests.post(url, headers=headers, json={})
        if post_response.status_code not in [200, 201]:
            print(f"❌ Failed to provision ngrok proxy: {post_response.text}")
            sys.exit(1)
        new_data = post_response.json()
        tunnel = new_data.get("tunnel")
        if not tunnel:
            print("❌ Ngrok proxy was not created successfully.")
            sys.exit(1)
        print("✅ Ngrok proxy created successfully.")
        save_ngrok_credentials(new_data)
        # Optionally, display the tunnel details for the user to copy:
        print("   Endpoint URL:", tunnel.get("endpoint_url"))
        print("   Seed:", tunnel.get("seed"))
        print("   Auth Token:", tunnel.get("auth_token"))
        return new_data

# --------------------------
# Now running the campaigns agent
# --------------------------
def remove_local_container(container_name):
    """
    Attempts to stop and remove a Docker container with the specified name.
    If the container does not exist or fails to stop/remove, a message is printed and the process continues.
    """
    try:
        print(f"ℹ️ Attempting to stop container '{container_name}'...")
        subprocess.run(["docker", "stop", container_name], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"ℹ️ Removing container '{container_name}'...")
        subprocess.run(["docker", "rm", container_name], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"✅ Local container '{container_name}' removed (if it existed).")
    except Exception as e:
        print(f"ℹ️ Could not stop/remove container '{container_name}': {e}")

def check_docker_installed():
    try:
        result = subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except Exception:
        return False

def container_running(container_name):
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", f"name=^{container_name}$", "--format", "{{.Names}}"],
            capture_output=True, text=True
        )
        return container_name in result.stdout.splitlines()
    except Exception as e:
        print("❌ Error checking docker containers:", e)
        sys.exit(1)

def run_docker_locally(ngrok_seed, ngrok_token, resourcely_api_token):
    """
    Runs the campaigns-agent container locally via Docker if it's not already running.
    Checks that Docker is installed and running.
    """
    container_name = "campaigns-agent"
    if not check_docker_installed():
        print("❌ Docker is not installed or not running. Please install/start Docker and try again.")
        sys.exit(1)
    if container_running(container_name):
        print(f"ℹ️ Docker container '{container_name}' is already running.")
        return

    docker_command = [
        "docker", "run", "--platform", "linux/amd64", "-d", "--name", container_name,
        "-e", "RESOURCELY_API_HOST=https://api.dev.resourcely.io",
        "-e", "AUTH0_AUDIENCE=https://campaigns-agent.dev.resourcely.io",
        "-e", "AUTH0_DOMAIN=https://login.portal.dev.resourcely.io",
        "-e", "APP_ENV=dev",
        "-e", f"RESOURCELY_NGROK_TUNNEL_SEED={ngrok_seed}",
        "-e", f"RESOURCELY_NGROK_TOKEN={ngrok_token}",
        "-e", f"RESOURCELY_API_TOKEN={resourcely_api_token}",
        "-v", os.path.expanduser("~/.aws") + ":/root/.aws:ro",
        "ghcr.io/resourcely-inc/campaigns-agent:dev-latest"
    ]
    print("ℹ️ Running docker container locally with command:")
    print(" ".join(docker_command))
    try:
        subprocess.run(docker_command, check=True)
        print("✅ Docker container started successfully.")
    except subprocess.CalledProcessError as e:
        print("❌ Failed to start docker container:", e)
        sys.exit(1)

def create_or_update_consolidated_secret(secret_name, secret_data, region, secrets_client):
    """
    Creates or updates a secret in AWS Secrets Manager with secret_data as a JSON object.
    secret_data is a dictionary containing key-value pairs.
    Returns the ARN of the secret.
    """
    try:
        # Try to describe the secret.
        response = secrets_client.describe_secret(SecretId=secret_name)
        # If it exists, update its value.
        secrets_client.put_secret_value(SecretId=secret_name, SecretString=json.dumps(secret_data))
        secret_arn = response["ARN"]
        print(f"✅ Updated consolidated secret '{secret_name}'. ARN: {secret_arn}")
    except secrets_client.exceptions.ResourceNotFoundException:
        # Secret doesn't exist; create it.
        response = secrets_client.create_secret(
            Name=secret_name,
            SecretString=json.dumps(secret_data),
            Description="Consolidated secrets for campaigns agent"
        )
        secret_arn = response["ARN"]
        print(f"✅ Created consolidated secret '{secret_name}'. ARN: {secret_arn}")
    except Exception as e:
        print(f"❌ Failed to create or update consolidated secret '{secret_name}': {e}")
        sys.exit(1)
    return secret_arn

def ensure_ecs_role(iam_client, role_name, bucket_name):
    """
    Ensure that an IAM role exists with the given role_name.
    The role will have a trust policy allowing ecs-tasks.amazonaws.com to assume it.
    An inline policy named "CampaignsAgentS3AndSecretsPolicy" is attached that allows:
      - S3: ListBucket, GetObject, PutObject, DeleteObject on the specified bucket.
      - SecretsManager: GetSecretValue on all resources.
    Returns the role ARN.
    """
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ecs-tasks.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    }
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowS3Access",
                "Effect": "Allow",
                "Action": [
                    "s3:ListBucket",
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:DeleteObject"
                ],
                "Resource": [
                    f"arn:aws:s3:::{bucket_name}",
                    f"arn:aws:s3:::{bucket_name}/*"
                ]
            },
            {
                "Sid": "AllowSecretsManagerAccess",
                "Effect": "Allow",
                "Action": [
                    "secretsmanager:GetSecretValue"
                ],
                "Resource": "*"
            }
        ]
    }
    policy_name = "CampaignsAgentS3AndSecretsPolicy"
    # Check if the role exists
    try:
        role_response = iam_client.get_role(RoleName=role_name)
        print(f"✅ IAM role '{role_name}' already exists.")
    except iam_client.exceptions.NoSuchEntityException:
        try:
            role_response = iam_client.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Description="Role for campaigns agent with access to S3 and Secrets Manager"
            )
            print(f"✅ Created IAM role '{role_name}'.")
            # Wait briefly for role propagation.
            time.sleep(5)
        except ClientError as e:
            print(f"❌ Failed to create IAM role '{role_name}':", e)
            sys.exit(1)
    # Attach or update the inline policy
    try:
        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(inline_policy)
        )
        print(f"✅ Attached inline policy '{policy_name}' to role '{role_name}'.")
    except ClientError as e:
        print(f"❌ Failed to attach inline policy to role '{role_name}':", e)
        sys.exit(1)
    role_arn = iam_client.get_role(RoleName=role_name)["Role"]["Arn"]
    return role_arn

def ensure_ecs_roles(iam_client, bucket_name):
    """
    Ensure that both the task role and the execution role exist.
    Returns a tuple (task_role_arn, execution_role_arn).
    """
    task_role_name = "resourcely_campaigns-agent-task-role"
    execution_role_name = "resourcely_campaigns-agent-execution-role"
    task_role_arn = ensure_ecs_role(iam_client, task_role_name, bucket_name)
    execution_role_arn = ensure_ecs_role(iam_client, execution_role_name, bucket_name)
    return task_role_arn, execution_role_arn

def ensure_ecs_cluster(ecs_client, cluster_name="resourcely-campaigns"):
    """
    Ensures that an ECS cluster with the given name exists.
    If it does not exist, creates the cluster.
    Returns the cluster name.
    """
    try:
        response = ecs_client.describe_clusters(clusters=[cluster_name])
        failures = response.get("failures", [])
        clusters = response.get("clusters", [])
        if failures or not clusters or clusters[0]["status"] != "ACTIVE":
            print(f"ℹ️ Cluster '{cluster_name}' not found. Creating cluster...")
            create_response = ecs_client.create_cluster(clusterName=cluster_name)
            print(f"✅ Cluster '{cluster_name}' created.")
        else:
            print(f"✅ ECS cluster '{cluster_name}' already exists.")
    except Exception as e:
        print("❌ Error ensuring ECS cluster exists:", e)
        sys.exit(1)
    return cluster_name

def select_vpc_network_config(aws_region, access_key, secret_key):
    """
    List available VPCs, prompt the user to choose one, then list subnets and security groups for that VPC.
    Returns a dictionary with keys "subnets" and "securityGroups" containing the chosen IDs.
    """
    ec2_client = boto3.client('ec2', aws_access_key_id=access_key,
                              aws_secret_access_key=secret_key, region_name=aws_region)
    
    # List available VPCs.
    try:
        vpcs_response = ec2_client.describe_vpcs()
    except Exception as e:
        print("❌ Failed to list VPCs:", e)
        sys.exit(1)
    
    vpcs = vpcs_response.get("Vpcs", [])
    if not vpcs:
        print("❌ No VPCs found.")
        sys.exit(1)
    
    print("\nAvailable VPCs:")
    for i, vpc in enumerate(vpcs):
        vpc_id = vpc["VpcId"]
        vpc_name = ""
        for tag in vpc.get("Tags", []):
            if tag["Key"] == "Name":
                vpc_name = tag["Value"]
        print(f"{i+1}: VPC ID: {vpc_id}, Name: {vpc_name}")
    
    vpc_choice = input("Enter the number of the VPC you want to use: ").strip()
    try:
        vpc_index = int(vpc_choice) - 1
        if vpc_index < 0 or vpc_index >= len(vpcs):
            raise ValueError("Invalid selection")
    except Exception as e:
        print("❌ Invalid VPC selection:", e)
        sys.exit(1)
    selected_vpc = vpcs[vpc_index]
    vpc_id = selected_vpc["VpcId"]
    print(f"✅ Selected VPC: {vpc_id}")
    
    # List subnets for the selected VPC.
    try:
        subnets_response = ec2_client.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
    except Exception as e:
        print("❌ Failed to list subnets:", e)
        sys.exit(1)
    subnets = subnets_response.get("Subnets", [])
    if not subnets:
        print("❌ No subnets found in the selected VPC.")
        sys.exit(1)
    
    print("\nAvailable Subnets in VPC", vpc_id)
    for i, subnet in enumerate(subnets):
        print(f"{i+1}: Subnet ID: {subnet['SubnetId']}, Availability Zone: {subnet['AvailabilityZone']}")
    
    subnet_input = input("Enter the numbers of subnets you want to use (comma separated, e.g., 1,2): ").strip()
    try:
        subnet_indices = [int(x.strip()) - 1 for x in subnet_input.split(",") if x.strip()]
        if not subnet_indices or any(idx < 0 or idx >= len(subnets) for idx in subnet_indices):
            raise ValueError("Invalid subnet selection")
    except Exception as e:
        print("❌ Invalid subnet selection:", e)
        sys.exit(1)
    chosen_subnets = [subnets[idx]["SubnetId"] for idx in subnet_indices]
    print(f"✅ Selected Subnets: {chosen_subnets}")
    
    # List security groups for the selected VPC.
    try:
        sgs_response = ec2_client.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
    except Exception as e:
        print("❌ Failed to list security groups:", e)
        sys.exit(1)
    security_groups = sgs_response.get("SecurityGroups", [])
    if not security_groups:
        print("❌ No security groups found in the selected VPC.")
        sys.exit(1)
    
    print("\nAvailable Security Groups in VPC", vpc_id)
    for i, sg in enumerate(security_groups):
        print(f"{i+1}: SG ID: {sg['GroupId']}, Name: {sg['GroupName']}")
    
    sg_input = input("Enter the numbers of security groups you want to use (comma separated, e.g., 1,2): ").strip()
    try:
        sg_indices = [int(x.strip()) - 1 for x in sg_input.split(",") if x.strip()]
        if not sg_indices or any(idx < 0 or idx >= len(security_groups) for idx in sg_indices):
            raise ValueError("Invalid security group selection")
    except Exception as e:
        print("❌ Invalid security group selection:", e)
        sys.exit(1)
    chosen_sgs = [security_groups[idx]["GroupId"] for idx in sg_indices]
    print(f"✅ Selected Security Groups: {chosen_sgs}")
    
    return {"subnets": chosen_subnets, "securityGroups": chosen_sgs}

def prompt_for_vpc_cidr():
    """
    Prompts the user to choose a CIDR block for the new VPC.
    Returns the selected CIDR block as a string.
    """
    options = ["10.0.0.0/16", "192.168.0.0/16", "172.31.0.0/16"]
    print("Please choose a CIDR block for the new VPC:")
    for i, cidr in enumerate(options, 1):
        print(f"{i}: {cidr}")
    choice = input("Enter option number (default 1): ").strip()
    try:
        idx = int(choice) - 1 if choice else 0
        if idx < 0 or idx >= len(options):
            raise ValueError("Invalid selection")
    except Exception as e:
        print("Invalid selection, defaulting to 10.0.0.0/16")
        idx = 0
    selected_vpc_cidr = options[idx]
    print(f"Selected VPC CIDR: {selected_vpc_cidr}")
    return selected_vpc_cidr

def compute_public_subnet_cidr(vpc_cidr):
    """
    Computes a default public subnet CIDR based on the selected VPC CIDR.
    """
    if vpc_cidr == "10.0.0.0/16":
        return "10.0.1.0/24"
    elif vpc_cidr == "192.168.0.0/16":
        return "192.168.1.0/24"
    elif vpc_cidr == "172.31.0.0/16":
        return "172.31.0.0/16"
    else:
        return "10.0.1.0/24"

def create_new_vpc_and_sg(aws_region, access_key, secret_key):
    """
    Idempotently creates (or reuses) a new VPC (tagged "resourcely-vpc") and associated resources:
      - Public Subnet (tagged "resourcely-public-subnet")
      - Internet Gateway (tagged "resourcely-igw")
      - Route Table (tagged "resourcely-public-rt") with a default route via the IGW
      - Security Group (named "resourcely-sg") with an outbound rule for 0.0.0.0/0.
    Prompts the user to choose a VPC CIDR block and computes a default public subnet CIDR.
    Returns a dictionary with keys: "vpc_id", "subnets" (list), and "securityGroups" (list).
    """
    ec2_client = boto3.client('ec2', aws_access_key_id=access_key,
                              aws_secret_access_key=secret_key, region_name=aws_region)
    
    # Prompt for VPC CIDR and compute default subnet CIDR.
    vpc_cidr = prompt_for_vpc_cidr()
    subnet_cidr = compute_public_subnet_cidr(vpc_cidr)
    
    # Check for existing VPC with tag Name=resourcely-vpc and matching CIDR.
    vpcs = ec2_client.describe_vpcs(
        Filters=[{"Name": "tag:Name", "Values": ["resourcely-vpc"]},
                 {"Name": "cidr-block", "Values": [vpc_cidr]}]
    ).get("Vpcs", [])
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        print(f"✅ Found existing VPC: {vpc_id} with CIDR {vpc_cidr}")
    else:
        vpc_response = ec2_client.create_vpc(CidrBlock=vpc_cidr)
        vpc_id = vpc_response["Vpc"]["VpcId"]
        ec2_client.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": "resourcely-vpc"}])
        print(f"✅ Created new VPC: {vpc_id} with CIDR {vpc_cidr}")
        waiter = ec2_client.get_waiter("vpc_available")
        waiter.wait(VpcIds=[vpc_id])
    
    # Check for existing public subnet in this VPC with tag "resourcely-public-subnet" and matching CIDR.
    subnets = ec2_client.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]},
                 {"Name": "tag:Name", "Values": ["resourcely-public-subnet"]},
                 {"Name": "cidr-block", "Values": [subnet_cidr]}]
    ).get("Subnets", [])
    if subnets:
        subnet_id = subnets[0]["SubnetId"]
        print(f"✅ Found existing public subnet: {subnet_id} with CIDR {subnet_cidr}")
    else:
        # Get an availability zone.
        azs = ec2_client.describe_availability_zones()["AvailabilityZones"]
        az = azs[0]["ZoneName"]
        subnet_response = ec2_client.create_subnet(VpcId=vpc_id, CidrBlock=subnet_cidr, AvailabilityZone=az)
        subnet_id = subnet_response["Subnet"]["SubnetId"]
        ec2_client.create_tags(Resources=[subnet_id], Tags=[{"Key": "Name", "Value": "resourcely-public-subnet"}])
        print(f"✅ Created public subnet: {subnet_id} in AZ {az} with CIDR {subnet_cidr}")
    
    # Check for an Internet Gateway with tag "resourcely-igw" attached to the VPC.
    igws = ec2_client.describe_internet_gateways(
        Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]},
                 {"Name": "tag:Name", "Values": ["resourcely-igw"]}]
    ).get("InternetGateways", [])
    if igws:
        igw_id = igws[0]["InternetGatewayId"]
        print(f"✅ Found existing Internet Gateway: {igw_id}")
    else:
        igw_response = ec2_client.create_internet_gateway()
        igw_id = igw_response["InternetGateway"]["InternetGatewayId"]
        ec2_client.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
        ec2_client.create_tags(Resources=[igw_id], Tags=[{"Key": "Name", "Value": "resourcely-igw"}])
        print(f"✅ Created and attached Internet Gateway: {igw_id}")
    
    # Check for an existing Route Table tagged "resourcely-public-rt" in this VPC.
    rts = ec2_client.describe_route_tables(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]},
                 {"Name": "tag:Name", "Values": ["resourcely-public-rt"]}]
    ).get("RouteTables", [])
    if rts:
        rt_id = rts[0]["RouteTableId"]
        print(f"✅ Found existing Route Table: {rt_id}")
    else:
        rt_response = ec2_client.create_route_table(VpcId=vpc_id)
        rt_id = rt_response["RouteTable"]["RouteTableId"]
        ec2_client.create_tags(Resources=[rt_id], Tags=[{"Key": "Name", "Value": "resourcely-public-rt"}])
        ec2_client.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
        ec2_client.associate_route_table(RouteTableId=rt_id, SubnetId=subnet_id)
        print(f"✅ Created and associated Route Table: {rt_id}")
    
    # Check for an existing Security Group named "resourcely-sg" in this VPC.
    sgs = ec2_client.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]},
                 {"Name": "group-name", "Values": ["resourcely-sg"]}]
    ).get("SecurityGroups", [])
    if sgs:
        sg_id = sgs[0]["GroupId"]
        print(f"✅ Found existing Security Group: {sg_id}")
    else:
        sg_response = ec2_client.create_security_group(
            GroupName="resourcely-sg", Description="Security group for campaigns agent", VpcId=vpc_id
        )
        sg_id = sg_response["GroupId"]
        print(f"✅ Created Security Group: {sg_id}")
    
    # Check if the security group already has an egress rule allowing outbound traffic to 0.0.0.0/0.
    try:
        sg_details = ec2_client.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
        existing_egress = sg_details.get("IpPermissionsEgress", [])
        rule_exists = False
        for rule in existing_egress:
            if rule.get("IpProtocol") == "-1":
                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        rule_exists = True
                        break
            if rule_exists:
                break
        if not rule_exists:
            ec2_client.authorize_security_group_egress(
                GroupId=sg_id,
                IpPermissions=[{
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                }]
            )
            print(f"✅ Authorized egress rule for Security Group '{sg_id}'.")
        else:
            print(f"ℹ️ Egress rule already exists for Security Group '{sg_id}'.")
    except ClientError as e:
        print(f"❌ Failed to authorize egress rule for Security Group '{sg_id}':", e)
        sys.exit(1)
    
    return {"vpc_id": vpc_id, "subnets": [subnet_id], "securityGroups": [sg_id]}

def select_or_create_vpc_network_config(aws_region, access_key, secret_key):
    """
    Prompt the user: either choose to create a new VPC or select from existing ones.
    If the user chooses 'y' (create new), then create a new VPC and security group.
    Otherwise, call your existing function select_vpc_network_config().
    Returns a dict with keys "subnets" and "securityGroups" containing the chosen IDs.
    """
    choice = input("Do you want to create a new VPC and security group? (y/n): ").strip().lower()
    if choice == "y":
        return create_new_vpc_and_sg(aws_region, access_key, secret_key)
    else:
        return select_vpc_network_config(aws_region, access_key, secret_key)

def deploy_as_ecs_service(ngrok_seed, ngrok_token, resourcely_api_token, iam_client, bucket_name, network_config, aws_region, access_key, secret_key):
    """
    Deploy the campaigns-agent container as an ECS service using Fargate.
    
    Steps:
      1. Read ngrok seed and token from local credentials.
      2. Create/update Secrets Manager entries for the ngrok seed and token.
      3. Ensure that the ECS task role and execution role exist with S3 and Secrets Manager access.
      4. Register a task definition (without any port mappings) that references secrets from Secrets Manager.
      5. Create the ECS service.
      
    This function is idempotent.
    """
    ecs_client = boto3.client('ecs', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=aws_region)
    sts_client = boto3.client('sts', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=aws_region)
    secrets_client = boto3.client('secretsmanager', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=aws_region)
    
    # Get AWS account ID to namespace the secrets
    account_id = get_account_id(sts_client)
    cluster_name = ensure_ecs_cluster(ecs_client, "resourcely-campaigns")
    service_name = "resourcely-campaigns-agent"
    
    # Check if the service already exists in the cluster.
    try:
        services = ecs_client.list_services(cluster=cluster_name)['serviceArns']
        if any(service_name in s for s in services):
            print(f"ℹ️ ECS service '{service_name}' already exists in cluster '{cluster_name}'.")
            return
    except ClientError as e:
        print("❌ Failed to list ECS services:", e)
        sys.exit(1)
    
    # Create or update secrets in Secrets Manager for ngrok seed and token.
    # Consolidate secrets: ngrok seed, ngrok token, and RESOURCELY_API_TOKEN.
    consolidated_secret_data = {
        "RESOURCELY_NGROK_TUNNEL_SEED": ngrok_seed,
        "RESOURCELY_NGROK_TOKEN": ngrok_token,
        "RESOURCELY_API_TOKEN": resourcely_api_token
    }
    consolidated_secret_name = f"campaigns_agent_resourcely_secrets_{account_id}"
    consolidated_secret_arn = create_or_update_consolidated_secret(consolidated_secret_name, consolidated_secret_data, aws_region, secrets_client)
    
    # Ensure IAM roles (task and execution) exist.
    task_role_arn, execution_role_arn = ensure_ecs_roles(iam_client, bucket_name)

    # Define container definitions.
    container_definitions = [
        {
            "name": "resourcely_campaigns_agent",
            "image": "ghcr.io/resourcely-inc/campaigns-agent:dev-latest",
            "cpu": 0,
            "portMappings": [],
            "essential": True,
            "environment": [
                {"name": "AUTH0_DOMAIN", "value": "https://login.portal.dev.resourcely.io"},
                {"name": "APP_ENV", "value": "dev"},
                {"name": "RESOURCELY_API_HOST", "value": "https://api.dev.resourcely.io"},
                {"name": "AUTH0_AUDIENCE", "value": "https://campaigns-agent.dev.resourcely.io"}
            ],
            "secrets": [
                {"name": "RESOURCELY_NGROK_TUNNEL_SEED", "valueFrom": f"{consolidated_secret_arn}:RESOURCELY_NGROK_TUNNEL_SEED::"},
                {"name": "RESOURCELY_NGROK_TOKEN", "valueFrom": f"{consolidated_secret_arn}:RESOURCELY_NGROK_TOKEN::"},
                {"name": "RESOURCELY_API_TOKEN", "valueFrom": f"{consolidated_secret_arn}:RESOURCELY_API_TOKEN::"}
            ]
        }
    ]
    
    # Register task definition.
    task_def_family = "resourcely_campaigns_agent"
    try:
        register_response = ecs_client.register_task_definition(
            family=task_def_family,
            requiresCompatibilities=["FARGATE"],
            networkMode="awsvpc",
            containerDefinitions=container_definitions,
            taskRoleArn=task_role_arn,
            executionRoleArn=execution_role_arn,
            cpu="1024",
            memory="3072"
        )
        task_def_arn = register_response["taskDefinition"]["taskDefinitionArn"]
        print(f"✅ Registered task definition: {task_def_arn}")
    except ClientError as e:
        print("❌ Failed to register task definition:", e)
        sys.exit(1)
    
    # Create the ECS service with Fargate launch type.
    try:
        ecs_client.create_service(
            cluster=cluster_name,
            serviceName=service_name,
            taskDefinition=task_def_arn,
            desiredCount=1,
            launchType="FARGATE",
            networkConfiguration={
                "awsvpcConfiguration": {
                    "subnets": network_config["subnets"],
                    "securityGroups": network_config["securityGroups"],
                    "assignPublicIp": "ENABLED"
                }
            }
        )
        print(f"✅ Created ECS service '{service_name}' in cluster '{cluster_name}'.")
    except ClientError as e:
        print("❌ Failed to create ECS service:", e)
        sys.exit(1)

def wait_for_ecs_service_running(ecs_client, cluster_name, service_name, timeout=300, poll_interval=10):
    """
    Poll the ECS service until at least one task is RUNNING.
    This function no longer checks container health status.
    If no tasks are found or they don't reach RUNNING within the timeout, the script exits.
    """
    start_time = time.time()
    print(f"ℹ️ Waiting for ECS service '{service_name}' in cluster '{cluster_name}' to have at least one RUNNING task...")
    while time.time() - start_time < timeout:
        try:
            task_arns = ecs_client.list_tasks(cluster=cluster_name, serviceName=service_name).get("taskArns", [])
        except Exception as e:
            print("❌ Error listing ECS tasks:", e)
            sys.exit(1)
        if not task_arns:
            print("ℹ️ No tasks found yet. Waiting...")
            time.sleep(poll_interval)
            continue

        try:
            tasks = ecs_client.describe_tasks(cluster=cluster_name, tasks=task_arns).get("tasks", [])
        except Exception as e:
            print("❌ Error describing ECS tasks:", e)
            sys.exit(1)

        for task in tasks:
            if task.get("lastStatus") == "RUNNING":
                print("✅ ECS service has a task in RUNNING state.")
                return

        print("ℹ️ Tasks are not yet RUNNING. Waiting...")
        time.sleep(poll_interval)
    
    print("❌ Timeout waiting for ECS service tasks to reach RUNNING state.")
    sys.exit(1)


def prompt_deployment_option():
    """
    Prompt the user to choose one of two deployment options:
    1: Run Docker locally with these credentials.
    2: Deploy the container as an ECS service in AWS using your AWS credentials.
    Returns "1" or "2".
    """
    print("\nPlease choose one of the following deployment options:")
    print("1: Run Docker locally with these credentials")
    print("2: Deploy the container as an ECS service in AWS using your AWS credentials")
    choice = input("Enter 1 or 2: ").strip()
    if choice not in ("1", "2"):
        print("❌ Invalid choice. Please run the script again and choose either 1 or 2.")
        sys.exit(1)
    return choice
        
# --------------------------
# Trigger campaigns scan 
# --------------------------
def get_tf_config_path(repository, resourcely_api_token):
    repo_url = f"https://github.com/{repository}"
    """
    Query the Resourcely Terraform configuration endpoint for the given repository URL.
    Extracts and returns the "path" from the first terraform_config in the response.
    """
    endpoint = "https://api.dev.resourcely.io/api/v1/terraform/config"
    params = {"repo_url": repo_url}
    headers = {
        "Authorization": f"Bearer {resourcely_api_token}",
        "Accept": "application/json"
    }
    try:
        response = requests.get(endpoint, headers=headers, params=params)
        if response.status_code != 200:
            print(f"❌ Failed to retrieve Terraform config (status code {response.status_code}): {response.text}")
            sys.exit(1)
        data = response.json()
        terraform_configs = data.get("terraform_configs", [])
        if not terraform_configs:
            print("❌ No terraform configurations found for the repository.")
            sys.exit(1)
        # Extract the "path" from the first configuration.
        tf_config = terraform_configs[0].get("terraform_config", {})
        tf_path = tf_config.get("path")
        if not tf_path:
            print("❌ Terraform config does not contain a 'path'.")
            sys.exit(1)
        print(f"✅ Retrieved Terraform config path: {tf_path}")
        return tf_path
    except Exception as e:
        print("❌ Exception while retrieving Terraform config:", e)
        sys.exit(1)

def trigger_evaluation_scan(repository, tf_config_root_path, resourcely_api_token):
    repo_url = f"https://github.com/{repository}"
    """
    Trigger a fresh scan by calling the POST endpoint:
      https://api.dev.resourcely.io/campaigns-api/v1/evaluations
    with a payload containing the repository URL and tf_config_root_path.
    
    Ensures that the response contains "status": "ASYNC_JOB_QUEUED".
    """
    endpoint = "https://api.dev.resourcely.io/campaigns-api/v1/evaluations"
    payload = {
        "repo_url": repo_url,
        "tf_config_root_path": tf_config_root_path
    }
    headers = {
        "Authorization": f"Bearer {resourcely_api_token}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    try:
        response = requests.post(endpoint, headers=headers, json=payload)
        if response.status_code not in [200, 201]:
            print(f"❌ Failed to trigger evaluation scan (status code {response.status_code}): {response.text}")
            sys.exit(1)
        data = response.json()
        # Check that the status is ASYNC_JOB_QUEUED.
        if data.get("status") != "ASYNC_JOB_QUEUED":
            print("❌ Unexpected scan status. Expected 'ASYNC_JOB_QUEUED' but got:", data.get("status"))
            print("Response:", json.dumps(data, indent=2))
            sys.exit(1)
        print("✅ Successfully triggered evaluation scan. Response:")
        return data
    except Exception as e:
        print("❌ Exception while triggering evaluation scan:", e)
        sys.exit(1)

# --------------------------
# Verify agent is up and running 
# --------------------------
def poll_agent_diagnostics(api_token, max_attempts=5, interval=5):
    """
    Polls the diagnostics endpoint to ensure that the following campaigns agent diagnostic checks are successful:
      - DIAGNOSTIC_TYPE_CAMPAIGNS_AGENT_REGISTERED
      - DIAGNOSTIC_TYPE_CAMPAIGNS_AGENT_REACHABLE
      - DIAGNOSTIC_TYPE_CAMPAIGNS_AGENT_EVALUATIONS
    Retries up to max_attempts times, waiting interval seconds between attempts.
    """
    url = "https://api.dev.resourcely.io/api/v1/diagnostics"
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Accept": "application/json"
    }
    required_checks = {
        "DIAGNOSTIC_TYPE_CAMPAIGNS_AGENT_REGISTERED": "DIAGNOSTIC_STATUS_SUCCESS",
        "DIAGNOSTIC_TYPE_CAMPAIGNS_AGENT_REACHABLE": "DIAGNOSTIC_STATUS_SUCCESS",
        "DIAGNOSTIC_TYPE_CAMPAIGNS_AGENT_EVALUATIONS": "DIAGNOSTIC_STATUS_SUCCESS"
    }
    attempt = 0
    while attempt < max_attempts:
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            print(f"❌ Failed to retrieve diagnostics (status code {response.status_code}): {response.text}")
            sys.exit(1)
        data = response.json()
        diagnostics = data.get("diagnostics", [])
        
        # Prepare a dictionary to collect statuses for our required checks.
        check_statuses = {k: None for k in required_checks.keys()}
        
        for diagnostic in diagnostics:
            for check in diagnostic.get("checks", []):
                ctype = check.get("type")
                cstatus = check.get("status")
                if ctype in required_checks:
                    # If not already success, update it.
                    if check_statuses[ctype] != "DIAGNOSTIC_STATUS_SUCCESS":
                        check_statuses[ctype] = cstatus
        
        # Determine if all required checks are successful.
        all_success = all(
            check_statuses[k] == required_checks[k] for k in required_checks
        )
        
        if all_success:
            print("✅ All campaigns agent diagnostics are successful:")
            return
        else:
            print("ℹ️ Campaigns agent diagnostics are not yet successful. Current statuses:")
            for k, v in check_statuses.items():
                print(f"   {k}: {v}")
        
        attempt += 1
        if attempt < max_attempts:
            print(f"ℹ️ Retrying in {interval} seconds... (attempt {attempt+1}/{max_attempts})")
            time.sleep(interval)
    
    print("❌ Timeout: Campaigns agent diagnostics did not become successful after maximum attempts.")
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
    resourcely_api_token = get_resourcely_api_token()
    check_resourcely_api_token(resourcely_api_token)
    verify_resourcely_api_token(resourcely_api_token)
    
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

     # Create S3 bucket for Terraform remote state
    print("\n✅ Creating S3 bucket for Terraform state...\n")
    s3_client = boto3.client('s3', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    sts_client = boto3.client('sts', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    new_bucket_name = create_s3_bucket(s3_client, sts_client)
    apply_bucket_policy(s3_client, sts_client, new_bucket_name)
    attach_s3_policy_to_role(iam_client, "ResourcelyGithubActionsOIDC", new_bucket_name)

    # Patch the terraform.tf and .resourcely.yaml file with the new bucket value.
    # (Terraform S3 backend requires the bucket name, not the ARN)
    patch_terraform_file(new_bucket_name)
    patch_resourcely_yaml(new_bucket_name)

    # Add RESOURCELY_API_TOKEN to github actions secrets 
    update_github_secret(owner, repo, token, "RESOURCELY_API_TOKEN", resourcely_api_token)

    # Now commit and push the changes and enable workflows
    update_main_tf_directly(new_versioning_status="Enabled")
    commit_sha = update_main_and_push()
    enable_workflows(owner, repo, token)
    wait_for_plan_job_success(owner, repo, commit_sha, token)
    
    # check if change management was setup in the account.
    check_change_management_setup(resourcely_api_token)

    # check if .resourcely.yaml was setup in the account.
    poll_yaml_config_diagnostics(resourcely_api_token, repository, max_attempts=5, interval=5)
    
    # check if vcs was setup in the account.
    poll_diagnostics(resourcely_api_token, max_attempts=5, interval=5)

    # check ngrok
    ensure_ngrok_setup(resourcely_api_token)

    # run campaigns agent
    ngrok_data = load_ngrok_credentials()
    if not ngrok_data:
        # If credentials file is missing (this shouldn't happen because ensure_ngrok_setup was called earlier),
        # call ensure_ngrok_setup to provision ngrok and save credentials.
        ngrok_data = ensure_ngrok_setup(resourcely_api_token)
    ngrok_tunnel = ngrok_data.get("tunnel", {})
    ngrok_seed = ngrok_tunnel.get("seed")
    ngrok_token = ngrok_tunnel.get("auth_token")
    
    # Prompt the user for deployment option
    option = prompt_deployment_option()
    
    if option == "1":
        run_docker_locally(ngrok_seed, ngrok_token, resourcely_api_token)
    elif option == "2":
        # Before deploying as ECS, stop and remove any locally running container named 'campaigns-agent'.
        remove_local_container("campaigns-agent")
        # Instead of selecting from existing VPCs, let the user choose to create a new one or pick an existing one.
        network_config = select_or_create_vpc_network_config(region, access_key, secret_key)
        deploy_as_ecs_service(ngrok_seed, ngrok_token, resourcely_api_token, iam_client, new_bucket_name, network_config, aws_region=region, access_key=access_key, secret_key=secret_key)
        ecs_client = boto3.client('ecs', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
        ecs_cluster = "resourcely-campaigns"
        service_name = "resourcely-campaigns-agent"
        wait_for_ecs_service_running(ecs_client, ecs_cluster, service_name, timeout=300, poll_interval=10)

    
    tf_config_path = get_tf_config_path(repository, resourcely_api_token)
    trigger_evaluation_scan(repository, tf_config_path, resourcely_api_token)

    # Now, poll the diagnostics endpoint to confirm the campaigns agent is reachable, registered, and its evaluations are successful.
    poll_agent_diagnostics(resourcely_api_token, max_attempts=5, interval=5)
    
    print("\n🚀 Onboarding complete! Now go to https://portal.dev.resourcely.io/remediation Happy hacking!...\n")

if __name__ == "__main__":
    main()
