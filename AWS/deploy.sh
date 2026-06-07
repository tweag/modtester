#!/bin/bash
# =============================================================================
# ModTester — Deploy All CloudFormation Stacks
#
# Deploys the 3 stacks in order:
#   1. ECS.yml      — VPC, Backend ECS, DynamoDB, S3, KMS, ALB
#   2. ECS-UI.yml   — UI ECS service (depends on stack 1 outputs)
#   3. VPN.yml      — Softether VPN for private access
#
# Prerequisites:
#   - AWS CLI v2 configured with appropriate permissions
#
# Usage:
#   ./deploy.sh                # Interactive — prompts for all values
#   ./deploy.sh --destroy      # Tear down all stacks
# =============================================================================
set -euo pipefail

# Resolve script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# =============================================================================
# Check for --destroy or --help
# =============================================================================
if [[ "${1:-}" == "--destroy" ]]; then
    DESTROY=true
    DESTROY_TARGET="${2:-all}"
    if [[ ! "$DESTROY_TARGET" =~ ^(all|backend|ui|vpn)$ ]]; then
        echo "Usage: $0 --destroy [all|backend|ui|vpn]"
        exit 1
    fi
elif [[ "${1:-}" == "--only" ]]; then
    ONLY_STACK="${2:-}"
    if [[ ! "$ONLY_STACK" =~ ^(backend|ui|vpn)$ ]]; then
        echo "Usage: $0 --only [backend|ui|vpn]"
        exit 1
    fi
    DESTROY=false
elif [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    echo "Usage: $0 [--destroy [STACK] | --only STACK | --help]"
    echo ""
    echo "  (no args)              Interactive deployment — all 3 stacks"
    echo "  --only backend         Deploy only the backend stack"
    echo "  --only ui              Deploy only the UI stack"
    echo "  --only vpn             Deploy only the VPN stack"
    echo "  --destroy              Tear down ALL stacks"
    echo "  --destroy backend      Tear down only the backend stack"
    echo "  --destroy ui           Tear down only the UI stack"
    echo "  --destroy vpn          Tear down only the VPN stack"
    echo "  --help                 Show this help"
    exit 0
else
    ONLY_STACK=""
    DESTROY=false
fi

# =============================================================================
# DESTROY MODE — runs immediately, only asks region/customer/env
# =============================================================================
if [ "$DESTROY" = true ]; then
    echo "=============================================="
    echo " ModTester — DESTROY Mode"
    echo "=============================================="
    echo ""
    read -p " AWS Region [us-east-2]: " REGION
    REGION="${REGION:-us-east-2}"

    read -p " CustomerName [modtester]: " CUSTOMER_NAME
    CUSTOMER_NAME="${CUSTOMER_NAME:-modtester}"

    read -p " EnvironmentName [dev]: " ENV_NAME
    ENV_NAME="${ENV_NAME:-dev}"

    BACKEND_STACK="${CUSTOMER_NAME}-${ENV_NAME}-backend"
    UI_STACK="${CUSTOMER_NAME}-${ENV_NAME}-ui"
    VPN_STACK="${CUSTOMER_NAME}-${ENV_NAME}-vpn"

    echo ""
    if [ "$DESTROY_TARGET" = "all" ]; then
        echo " Will delete ALL stacks:"
        echo "   • ${VPN_STACK}"
        echo "   • ${UI_STACK}"
        echo "   • ${BACKEND_STACK}"
        echo "   • All files in S3 buckets"
        echo "   • All ECR images"
    else
        case $DESTROY_TARGET in
            backend) echo " Will delete: ${BACKEND_STACK}" ;;
            ui)      echo " Will delete: ${UI_STACK}" ;;
            vpn)     echo " Will delete: ${VPN_STACK}" ;;
        esac
    fi
    echo ""
    read -p " ⚠️  Type 'yes' to confirm DESTRUCTION: " DESTROY_CONFIRM
    if [ "$DESTROY_CONFIRM" != "yes" ]; then
        echo " Aborted."
        exit 0
    fi

    echo ""

    # --- Clean S3 and ECR only when destroying all or backend ---
    if [ "$DESTROY_TARGET" = "all" ] || [ "$DESTROY_TARGET" = "backend" ]; then
        echo "[*] Emptying S3 bucket files..."

        # Find all buckets by name prefix
        for BUCKET in $(aws s3api list-buckets --query "Buckets[?starts_with(Name, '${CUSTOMER_NAME}-${ENV_NAME}') || starts_with(Name, '${CUSTOMER_NAME}')].Name" --output text --region "${REGION}" 2>/dev/null); do
            echo "   Removing all objects from: ${BUCKET}"
            aws s3 rm "s3://${BUCKET}" --recursive --region "${REGION}" 2>/dev/null || true
            VERSIONS=$(aws s3api list-object-versions --bucket "${BUCKET}" --region "${REGION}" \
                --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}}' --output json 2>/dev/null || echo '{"Objects":[]}')
            if [ "$VERSIONS" != '{"Objects":[]}' ] && [ "$VERSIONS" != '{"Objects":null}' ]; then
                echo "$VERSIONS" | aws s3api delete-objects --bucket "${BUCKET}" --delete file:///dev/stdin --region "${REGION}" 2>/dev/null || true
            fi
            MARKERS=$(aws s3api list-object-versions --bucket "${BUCKET}" --region "${REGION}" \
                --query '{Objects: DeleteMarkers[].{Key:Key,VersionId:VersionId}}' --output json 2>/dev/null || echo '{"Objects":[]}')
            if [ "$MARKERS" != '{"Objects":[]}' ] && [ "$MARKERS" != '{"Objects":null}' ]; then
                echo "$MARKERS" | aws s3api delete-objects --bucket "${BUCKET}" --delete file:///dev/stdin --region "${REGION}" 2>/dev/null || true
            fi
            echo "   ✅ ${BUCKET} emptied"
        done

        # Also empty ArtifactBucket from the stack (CloudFormation auto-names it)
        ARTIFACT_BUCKET=$(aws cloudformation describe-stack-resource --stack-name "${BACKEND_STACK}" --logical-resource-id ArtifactBucket --region "${REGION}" --query 'StackResourceDetail.PhysicalResourceId' --output text 2>/dev/null || echo "")
        if [ -n "$ARTIFACT_BUCKET" ] && [ "$ARTIFACT_BUCKET" != "None" ]; then
            echo "   Removing all objects from ArtifactBucket: ${ARTIFACT_BUCKET}"
            aws s3 rm "s3://${ARTIFACT_BUCKET}" --recursive --region "${REGION}" 2>/dev/null || true
            VERSIONS=$(aws s3api list-object-versions --bucket "${ARTIFACT_BUCKET}" --region "${REGION}" \
                --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}}' --output json 2>/dev/null || echo '{"Objects":[]}')
            if [ "$VERSIONS" != '{"Objects":[]}' ] && [ "$VERSIONS" != '{"Objects":null}' ]; then
                echo "$VERSIONS" | aws s3api delete-objects --bucket "${ARTIFACT_BUCKET}" --delete file:///dev/stdin --region "${REGION}" 2>/dev/null || true
            fi
            echo "   ✅ ${ARTIFACT_BUCKET} emptied"
        fi

        # Empty UI stack ArtifactBucket too
        UI_ARTIFACT_BUCKET=$(aws cloudformation describe-stack-resource --stack-name "${UI_STACK}" --logical-resource-id ArtifactBucket --region "${REGION}" --query 'StackResourceDetail.PhysicalResourceId' --output text 2>/dev/null || echo "")
        if [ -n "$UI_ARTIFACT_BUCKET" ] && [ "$UI_ARTIFACT_BUCKET" != "None" ]; then
            echo "   Removing all objects from UI ArtifactBucket: ${UI_ARTIFACT_BUCKET}"
            aws s3 rm "s3://${UI_ARTIFACT_BUCKET}" --recursive --region "${REGION}" 2>/dev/null || true
            VERSIONS=$(aws s3api list-object-versions --bucket "${UI_ARTIFACT_BUCKET}" --region "${REGION}" \
                --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}}' --output json 2>/dev/null || echo '{"Objects":[]}')
            if [ "$VERSIONS" != '{"Objects":[]}' ] && [ "$VERSIONS" != '{"Objects":null}' ]; then
                echo "$VERSIONS" | aws s3api delete-objects --bucket "${UI_ARTIFACT_BUCKET}" --delete file:///dev/stdin --region "${REGION}" 2>/dev/null || true
            fi
            echo "   ✅ ${UI_ARTIFACT_BUCKET} emptied"
        fi

        echo "[*] Deleting ECR repository images and repositories..."
        for REPO in $(aws ecr describe-repositories --query "repositories[?starts_with(repositoryName, '${CUSTOMER_NAME}')].repositoryName" --output text --region "${REGION}" 2>/dev/null); do
            echo "   Deleting: ${REPO}"
            aws ecr delete-repository --repository-name "${REPO}" --force --region "${REGION}" 2>/dev/null || true
            echo "   ✅ ${REPO} deleted"
        done
    fi

    # --- Delete stacks ---
    if [ "$DESTROY_TARGET" = "all" ] || [ "$DESTROY_TARGET" = "vpn" ]; then
        # Empty VPN S3 bucket first
        echo "[*] Emptying VPN S3 bucket files..."
        VPN_BUCKET=$(aws cloudformation describe-stack-resource --stack-name "${VPN_STACK}" --logical-resource-id VPNConfigBucket --region "${REGION}" --query 'StackResourceDetail.PhysicalResourceId' --output text 2>/dev/null || echo "")
        if [ -n "$VPN_BUCKET" ] && [ "$VPN_BUCKET" != "None" ]; then
            aws s3 rm "s3://${VPN_BUCKET}" --recursive --region "${REGION}" 2>/dev/null || true
            VERSIONS=$(aws s3api list-object-versions --bucket "${VPN_BUCKET}" --region "${REGION}" \
                --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}}' --output json 2>/dev/null || echo '{"Objects":[]}')
            if [ "$VERSIONS" != '{"Objects":[]}' ] && [ "$VERSIONS" != '{"Objects":null}' ]; then
                echo "$VERSIONS" | aws s3api delete-objects --bucket "${VPN_BUCKET}" --delete file:///dev/stdin --region "${REGION}" 2>/dev/null || true
            fi
            MARKERS=$(aws s3api list-object-versions --bucket "${VPN_BUCKET}" --region "${REGION}" \
                --query '{Objects: DeleteMarkers[].{Key:Key,VersionId:VersionId}}' --output json 2>/dev/null || echo '{"Objects":[]}')
            if [ "$MARKERS" != '{"Objects":[]}' ] && [ "$MARKERS" != '{"Objects":null}' ]; then
                echo "$MARKERS" | aws s3api delete-objects --bucket "${VPN_BUCKET}" --delete file:///dev/stdin --region "${REGION}" 2>/dev/null || true
            fi
            echo "   ✅ ${VPN_BUCKET} emptied"
        fi

        echo "[*] Deleting VPN stack: ${VPN_STACK}..."
        aws cloudformation delete-stack --stack-name "${VPN_STACK}" --region "${REGION}" 2>/dev/null || true
        aws cloudformation wait stack-delete-complete --stack-name "${VPN_STACK}" --region "${REGION}" 2>/dev/null || true
        echo "   ✅ Done"
    fi

    if [ "$DESTROY_TARGET" = "all" ] || [ "$DESTROY_TARGET" = "ui" ]; then
        echo "[*] Deleting UI stack: ${UI_STACK}..."
        aws cloudformation delete-stack --stack-name "${UI_STACK}" --region "${REGION}" 2>/dev/null || true
        aws cloudformation wait stack-delete-complete --stack-name "${UI_STACK}" --region "${REGION}" 2>/dev/null || true
        echo "   ✅ Done"
    fi

    if [ "$DESTROY_TARGET" = "all" ] || [ "$DESTROY_TARGET" = "backend" ]; then
        echo "[*] Deleting Backend stack: ${BACKEND_STACK}..."
        aws cloudformation delete-stack --stack-name "${BACKEND_STACK}" --region "${REGION}" 2>/dev/null || true
        aws cloudformation wait stack-delete-complete --stack-name "${BACKEND_STACK}" --region "${REGION}" 2>/dev/null || true
        echo "   ✅ Done"
    fi

    echo ""
    echo "✅ Destroy complete."
    exit 0
fi

# =============================================================================
# Collect variables from the user (only what's needed)
# =============================================================================
echo "=============================================="
echo " ModTester — AWS Deployment Configuration"
echo "=============================================="
echo ""
echo " Press Enter to accept [default] values."
echo ""

# --- General (always needed) ---
echo "─── General ───────────────────────────────────"
read -p " AWS Region [us-east-2]: " REGION
REGION="${REGION:-us-east-2}"

read -p " CustomerName [modtester]: " CUSTOMER_NAME
CUSTOMER_NAME="${CUSTOMER_NAME:-modtester}"

read -p " EnvironmentName (dev/staging/prod) [dev]: " ENV_NAME
ENV_NAME="${ENV_NAME:-dev}"

# --- Networking (backend only) ---
if [ -z "$ONLY_STACK" ] || [ "$ONLY_STACK" = "backend" ]; then
echo ""
echo "─── Networking ─────────────────────────────────"
read -p " VPCNET [10.0.0.0/16]: " VPCNET
VPCNET="${VPCNET:-10.0.0.0/16}"

read -p " PublicOneNET [10.0.0.0/24]: " PUBLIC_ONE_NET
PUBLIC_ONE_NET="${PUBLIC_ONE_NET:-10.0.0.0/24}"

read -p " PublicTwoNET [10.0.1.0/24]: " PUBLIC_TWO_NET
PUBLIC_TWO_NET="${PUBLIC_TWO_NET:-10.0.1.0/24}"

read -p " PrivateOneNET [10.0.2.0/24]: " PRIVATE_ONE_NET
PRIVATE_ONE_NET="${PRIVATE_ONE_NET:-10.0.2.0/24}"

read -p " PrivateTwoNET [10.0.3.0/24]: " PRIVATE_TWO_NET
PRIVATE_TWO_NET="${PRIVATE_TWO_NET:-10.0.3.0/24}"
fi

# --- TLS (backend and ui) ---
CERTIFICATE_ARN=""
PUBLIC_DOMAIN=""
LOCAL_DOMAIN=""
ROUTE53_ZONE_ID=""

if [ -z "$ONLY_STACK" ] || [ "$ONLY_STACK" = "backend" ] || [ "$ONLY_STACK" = "ui" ]; then
echo ""
echo "─── Domain & TLS ─────────────────────────────────"
echo "   Provide a Route53 domain to auto-create a wildcard certificate."
echo "   Leave empty for HTTP only (no TLS)."
echo ""
read -p " Domain name (e.g. modtester.example.com) []: " PUBLIC_DOMAIN

if [ -n "$PUBLIC_DOMAIN" ]; then
    LOCAL_DOMAIN="${PUBLIC_DOMAIN}"
    echo ""
    echo "   Looking up Route53 hosted zone for '${PUBLIC_DOMAIN}'..."
    ROUTE53_ZONE_ID=$(aws route53 list-hosted-zones-by-name \
        --dns-name "${PUBLIC_DOMAIN}" \
        --query "HostedZones[?Name=='${PUBLIC_DOMAIN}.'].Id" \
        --output text 2>/dev/null | head -1 | sed 's|/hostedzone/||')
    if [ -z "$ROUTE53_ZONE_ID" ] || [ "$ROUTE53_ZONE_ID" = "None" ]; then
        echo "   ⚠️  No Route53 hosted zone found for '${PUBLIC_DOMAIN}'"
        read -p "   Enter Hosted Zone ID manually (or leave empty for HTTP only): " ROUTE53_ZONE_ID
        ROUTE53_ZONE_ID="${ROUTE53_ZONE_ID:-}"
    else
        echo "   ✅ Hosted zone found: ${ROUTE53_ZONE_ID}"
        echo "   → Will create wildcard cert *.${PUBLIC_DOMAIN}"
        echo "   → DNS records: api.${PUBLIC_DOMAIN}, ui.${PUBLIC_DOMAIN}"
    fi
else
    echo "   → HTTP only (no TLS, no custom domain)"
fi
fi

# --- ECS / Compute (backend only) ---
if [ -z "$ONLY_STACK" ] || [ "$ONLY_STACK" = "backend" ]; then
echo ""
echo "─── ECS / Compute ──────────────────────────────"
read -p " InstanceType [t3a.large]: " INSTANCE_TYPE
INSTANCE_TYPE="${INSTANCE_TYPE:-t3a.large}"

read -p " ECSAMI (SSM path) [/aws/service/ecs/optimized-ami/amazon-linux-2/recommended/image_id]: " ECS_AMI
ECS_AMI="${ECS_AMI:-/aws/service/ecs/optimized-ami/amazon-linux-2/recommended/image_id}"

read -p " DesiredCapacity [1]: " DESIRED_CAPACITY
DESIRED_CAPACITY="${DESIRED_CAPACITY:-1}"

read -p " MaxSize [2]: " MAX_SIZE
MAX_SIZE="${MAX_SIZE:-2}"

read -p " ImageTag [latest]: " IMAGE_TAG
IMAGE_TAG="${IMAGE_TAG:-latest}"

# Always 0 for first deploy — pipeline scales up after first build
DESIRED_TASK_COUNT=0
fi

# --- AI / Backend (backend only) ---
if [ -z "$ONLY_STACK" ] || [ "$ONLY_STACK" = "backend" ]; then
echo ""
echo "─── AI / Backend ───────────────────────────────"
read -p " BedrockModel [us.anthropic.claude-opus-4-8]: " BEDROCK_MODEL
BEDROCK_MODEL="${BEDROCK_MODEL:-us.anthropic.claude-opus-4-8}"

read -sp " AuthSecret (JWT signing key) [modtester-secret]: " AUTH_SECRET
echo ""
AUTH_SECRET="${AUTH_SECRET:?ERROR: AuthSecret must be provided}"

echo ""
echo "─── Web UI Credentials ─────────────────────────"
read -p " UI Username [admin]: " UI_USERNAME
UI_USERNAME="${UI_USERNAME:-admin}"

read -sp " UI Password [ModTester@2026!]: " DEMO_PASSWORD
echo ""
DEMO_PASSWORD="${DEMO_PASSWORD:?ERROR: DemoPassword must be provided}"
fi

# --- CI/CD (backend and ui) ---
if [ -z "$ONLY_STACK" ] || [ "$ONLY_STACK" = "backend" ] || [ "$ONLY_STACK" = "ui" ]; then
echo ""
echo "─── CI/CD (leave empty to skip pipeline) ──────"
read -p " GitHubRepo (e.g. user/repo) []: " GITHUB_REPO
GITHUB_REPO="${GITHUB_REPO:-}"

read -p " GitHubBranch [main]: " GITHUB_BRANCH
GITHUB_BRANCH="${GITHUB_BRANCH:-main}"

read -p " GitHubConnectionArn []: " GITHUB_CONNECTION_ARN
GITHUB_CONNECTION_ARN="${GITHUB_CONNECTION_ARN:-}"
fi

# --- VPN (vpn only) ---
if [ -z "$ONLY_STACK" ] || [ "$ONLY_STACK" = "vpn" ]; then
echo ""
echo "─── VPN Configuration ──────────────────────────"
read -p " VPN Hub Name [ModTester]: " VPN_HUB_NAME
VPN_HUB_NAME="${VPN_HUB_NAME:-ModTester}"

read -sp " IPsec Pre-Shared Key [ModTester2026]: " VPN_PSK
echo ""
VPN_PSK="${VPN_PSK:?ERROR: VPN PSK must be provided}"

read -sp " Softether Admin Password [Modtester*2026]: " VPN_PASSWORD
echo ""
VPN_PASSWORD="${VPN_PASSWORD:?ERROR: VPN admin password must be provided}"

read -p " VPN Username [modtester]: " VPN_USERNAME
VPN_USERNAME="${VPN_USERNAME:-modtester}"

read -sp " VPN User Password [ModTester@2026!]: " VPN_USER_PASSWORD
echo ""
VPN_USER_PASSWORD="${VPN_USER_PASSWORD:?ERROR: VPN user password must be provided}"
fi

# --- Derived values ---
BACKEND_STACK="${CUSTOMER_NAME}-${ENV_NAME}-backend"
UI_STACK="${CUSTOMER_NAME}-${ENV_NAME}-ui"
VPN_STACK="${CUSTOMER_NAME}-${ENV_NAME}-vpn"

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text --region "${REGION}")

if [ -n "$ROUTE53_ZONE_ID" ]; then
    TLS_MODE="Wildcard cert (*.${LOCAL_DOMAIN})"
else
    TLS_MODE="HTTP only (no TLS)"
fi

# =============================================================================
# Confirm
# =============================================================================
echo ""
echo "=============================================="
echo " Deployment Summary"
echo "=============================================="
echo " Region:          ${REGION}"
echo " Account:         ${ACCOUNT_ID}"
echo " Customer:        ${CUSTOMER_NAME}"
echo " Environment:     ${ENV_NAME}"
if [ -z "$ONLY_STACK" ] || [ "$ONLY_STACK" = "backend" ]; then
echo " VPC CIDR:        ${VPCNET}"
echo " Domain:          ${LOCAL_DOMAIN}"
echo " TLS:             ${TLS_MODE}"
echo " Instance:        ${INSTANCE_TYPE} (capacity: ${DESIRED_CAPACITY}, max: ${MAX_SIZE})"
echo " Bedrock Model:   ${BEDROCK_MODEL}"
echo " CI/CD:           ${GITHUB_REPO:-disabled}"
fi
if [ -z "$ONLY_STACK" ] || [ "$ONLY_STACK" = "vpn" ]; then
echo " VPN Hub:         ${VPN_HUB_NAME:-N/A}"
echo " VPN User:        ${VPN_USERNAME:-N/A}"
fi
echo ""
if [ -z "$ONLY_STACK" ]; then
echo " Stacks:"
echo "   1. ${BACKEND_STACK}"
echo "   2. ${UI_STACK}"
echo "   3. ${VPN_STACK}"
else
echo " Stack: ${CUSTOMER_NAME}-${ENV_NAME}-${ONLY_STACK}"
fi
echo "=============================================="
echo ""

read -p " Proceed with deployment? (yes/no) [yes]: " CONFIRM
CONFIRM="${CONFIRM:-yes}"
if [ "$CONFIRM" != "yes" ]; then
    echo " Aborted."
    exit 0
fi

# =============================================================================
# Helper functions
# =============================================================================
wait_for_stack() {
    local stack_name=$1
    local action=$2

    echo "   Waiting for stack ${action}..."
    if aws cloudformation wait "stack-${action}-complete" --stack-name "${stack_name}" --region "${REGION}" 2>/dev/null; then
        echo "   ✅ Stack ${stack_name} ${action}d successfully."
    else
        echo "   ❌ Stack ${stack_name} ${action} failed!"
        aws cloudformation describe-stack-events \
            --stack-name "${stack_name}" \
            --region "${REGION}" \
            --query 'StackEvents[?ResourceStatus==`CREATE_FAILED` || ResourceStatus==`UPDATE_FAILED`].[LogicalResourceId,ResourceStatusReason]' \
            --output table | head -20
        exit 1
    fi
}

get_stack_output() {
    local stack_name=$1
    local output_key=$2
    aws cloudformation describe-stacks \
        --stack-name "${stack_name}" \
        --region "${REGION}" \
        --query "Stacks[0].Outputs[?OutputKey=='${output_key}'].OutputValue" \
        --output text
}

deploy_stack() {
    local stack_name=$1
    local template=$2
    shift 2
    local params=("$@")

    echo "   Template: ${template}"

    if aws cloudformation describe-stacks --stack-name "${stack_name}" --region "${REGION}" &>/dev/null; then
        echo "   Stack exists — updating..."
        aws cloudformation update-stack \
            --stack-name "${stack_name}" \
            --template-body "file://${template}" \
            --parameters "${params[@]}" \
            --capabilities CAPABILITY_NAMED_IAM CAPABILITY_IAM \
            --region "${REGION}" 2>/dev/null || {
                echo "   No changes to deploy (stack is up to date)."
                return 0
            }
        wait_for_stack "${stack_name}" "update"
    else
        echo "   Creating new stack..."
        aws cloudformation create-stack \
            --stack-name "${stack_name}" \
            --template-body "file://${template}" \
            --parameters "${params[@]}" \
            --capabilities CAPABILITY_NAMED_IAM CAPABILITY_IAM \
            --region "${REGION}"
        wait_for_stack "${stack_name}" "create"
    fi
}

# =============================================================================
# Step 1: Deploy Backend Stack (ECS.yml)
# =============================================================================
if [ -z "$ONLY_STACK" ] || [ "$ONLY_STACK" = "backend" ]; then
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[1/3] Deploying Backend Stack: ${BACKEND_STACK}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Clean up existing DNS records that might conflict
if [ -n "$ROUTE53_ZONE_ID" ] && [ -n "$LOCAL_DOMAIN" ]; then
    echo "   Cleaning up existing DNS records if any..."
    for RECORD_NAME in "api.${LOCAL_DOMAIN}" "ui.${LOCAL_DOMAIN}"; do
        EXISTING=$(aws route53 list-resource-record-sets \
            --hosted-zone-id "$ROUTE53_ZONE_ID" \
            --query "ResourceRecordSets[?Name=='${RECORD_NAME}.']" \
            --output json --region "${REGION}" 2>/dev/null || echo "[]")
        if [ "$EXISTING" != "[]" ] && [ -n "$EXISTING" ]; then
            aws route53 change-resource-record-sets \
                --hosted-zone-id "$ROUTE53_ZONE_ID" \
                --change-batch "{\"Changes\":[{\"Action\":\"DELETE\",\"ResourceRecordSet\":$(echo "$EXISTING" | python3 -c 'import sys,json;print(json.dumps(json.load(sys.stdin)[0]))' 2>/dev/null)}]}" \
                --region "${REGION}" 2>/dev/null || true
        fi
    done
fi

deploy_stack "${BACKEND_STACK}" "${SCRIPT_DIR}/ECS.yml" \
    "ParameterKey=CustomerName,ParameterValue=${CUSTOMER_NAME}" \
    "ParameterKey=EnvironmentName,ParameterValue=${ENV_NAME}" \
    "ParameterKey=VPCNET,ParameterValue=${VPCNET}" \
    "ParameterKey=PublicOneNET,ParameterValue=${PUBLIC_ONE_NET}" \
    "ParameterKey=PublicTwoNET,ParameterValue=${PUBLIC_TWO_NET}" \
    "ParameterKey=PrivateOneNET,ParameterValue=${PRIVATE_ONE_NET}" \
    "ParameterKey=PrivateTwoNET,ParameterValue=${PRIVATE_TWO_NET}" \
    "ParameterKey=LocalDomainName,ParameterValue=${LOCAL_DOMAIN}" \
    "ParameterKey=Route53HostedZoneId,ParameterValue=${ROUTE53_ZONE_ID}" \
    "ParameterKey=InstanceType,ParameterValue=${INSTANCE_TYPE}" \
    "ParameterKey=ECSAMI,ParameterValue=${ECS_AMI}" \
    "ParameterKey=DesiredCapacity,ParameterValue=${DESIRED_CAPACITY}" \
    "ParameterKey=MaxSize,ParameterValue=${MAX_SIZE}" \
    "ParameterKey=DesiredTaskCount,ParameterValue=${DESIRED_TASK_COUNT}" \
    "ParameterKey=ImageTag,ParameterValue=${IMAGE_TAG}" \
    "ParameterKey=BedrockModel,ParameterValue=${BEDROCK_MODEL}" \
    "ParameterKey=AuthSecret,ParameterValue=${AUTH_SECRET}" \
    "ParameterKey=DemoPassword,ParameterValue=${DEMO_PASSWORD}" \
    "ParameterKey=UIUsername,ParameterValue=${UI_USERNAME}" \
    "ParameterKey=GitHubRepo,ParameterValue=${GITHUB_REPO}" \
    "ParameterKey=GitHubBranch,ParameterValue=${GITHUB_BRANCH}" \
    "ParameterKey=GitHubConnectionArn,ParameterValue=${GITHUB_CONNECTION_ARN}"

# Scale backend service to 1 after stack is ready
echo ""
echo "   Setting backend ECS service to 1 desired task..."
ECS_CLUSTER_NAME=$(get_stack_output "${BACKEND_STACK}" "ECSClusterName" 2>/dev/null || echo "")
BACKEND_SERVICE=$(aws ecs list-services --cluster "$ECS_CLUSTER_NAME" --region "${REGION}" --query 'serviceArns[0]' --output text 2>/dev/null | awk -F/ '{print $NF}')
if [ -n "$BACKEND_SERVICE" ] && [ "$BACKEND_SERVICE" != "None" ]; then
    aws ecs update-service --cluster "$ECS_CLUSTER_NAME" --service "$BACKEND_SERVICE" --desired-count 1 --region "${REGION}" > /dev/null 2>&1 || true
    echo "   ✅ Backend service scaled to 1"
fi
fi

echo ""

# =============================================================================
# Step 2: Deploy UI Stack (ECS-UI.yml)
# =============================================================================
if [ -z "$ONLY_STACK" ] || [ "$ONLY_STACK" = "ui" ]; then
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[2/3] Deploying UI Stack: ${UI_STACK}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Get outputs from backend stack
VPC_ID=$(get_stack_output "${BACKEND_STACK}" "VPCId")
PRIVATE_SUBNET_ONE=$(get_stack_output "${BACKEND_STACK}" "PrivateSubnetOneId")
PRIVATE_SUBNET_TWO=$(get_stack_output "${BACKEND_STACK}" "PrivateSubnetTwoId")
CONTAINER_SG=$(get_stack_output "${BACKEND_STACK}" "ContainerSecurityGroupId")
ECS_CLUSTER=$(get_stack_output "${BACKEND_STACK}" "ECSClusterName")
CERT_ARN_FROM_BACKEND=$(get_stack_output "${BACKEND_STACK}" "CertificateArnOutput" 2>/dev/null || echo "")

# Use custom domain for backend URL (what the UI will use to reach the API)
if [ -n "$ROUTE53_ZONE_ID" ] && [ -n "$LOCAL_DOMAIN" ]; then
    BACKEND_URL="https://api.${LOCAL_DOMAIN}"
elif [ -n "$LOCAL_DOMAIN" ]; then
    BACKEND_URL="http://api.${LOCAL_DOMAIN}"
else
    BACKEND_URL=$(get_stack_output "${BACKEND_STACK}" "LoadBalancerURL" 2>/dev/null || echo "http://localhost:8000")
fi

echo "   Backend outputs:"
echo "     VPC:            ${VPC_ID}"
echo "     Subnets:        ${PRIVATE_SUBNET_ONE}, ${PRIVATE_SUBNET_TWO}"
echo "     ECS Cluster:    ${ECS_CLUSTER}"
echo "     Backend URL:    ${BACKEND_URL}"
if [ -n "$CERT_ARN_FROM_BACKEND" ]; then
echo "     Certificate:    ${CERT_ARN_FROM_BACKEND}"
fi

deploy_stack "${UI_STACK}" "${SCRIPT_DIR}/ECS-UI.yml" \
    "ParameterKey=CustomerName,ParameterValue=${CUSTOMER_NAME}-ui" \
    "ParameterKey=EnvironmentName,ParameterValue=${ENV_NAME}" \
    "ParameterKey=ECSClusterName,ParameterValue=${ECS_CLUSTER}" \
    "ParameterKey=BackendAPIURL,ParameterValue=${BACKEND_URL}" \
    "ParameterKey=VPCId,ParameterValue=${VPC_ID}" \
    "ParameterKey=PrivateSubnetOne,ParameterValue=${PRIVATE_SUBNET_ONE}" \
    "ParameterKey=PrivateSubnetTwo,ParameterValue=${PRIVATE_SUBNET_TWO}" \
    "ParameterKey=ContainerSecurityGroupId,ParameterValue=${CONTAINER_SG}" \
    "ParameterKey=LocalDomainName,ParameterValue=${LOCAL_DOMAIN}" \
    "ParameterKey=PrivateHostedZoneId,ParameterValue=${ROUTE53_ZONE_ID}" \
    "ParameterKey=CertificateArn,ParameterValue=${CERT_ARN_FROM_BACKEND}" \
    "ParameterKey=ImageTag,ParameterValue=${IMAGE_TAG}" \
    "ParameterKey=DesiredTaskCount,ParameterValue=${DESIRED_TASK_COUNT}" \
    "ParameterKey=GitHubRepo,ParameterValue=${GITHUB_REPO}" \
    "ParameterKey=GitHubBranch,ParameterValue=${GITHUB_BRANCH}" \
    "ParameterKey=GitHubConnectionArn,ParameterValue=${GITHUB_CONNECTION_ARN}"

# Scale UI service to 1 after stack is ready
echo ""
echo "   Setting UI ECS service to 1 desired task..."
UI_SERVICE=$(aws ecs list-services --cluster "$ECS_CLUSTER_NAME" --region "${REGION}" --query "serviceArns[?contains(@, 'ui')]" --output text 2>/dev/null | head -1 | awk -F/ '{print $NF}')
if [ -n "$UI_SERVICE" ] && [ "$UI_SERVICE" != "None" ]; then
    aws ecs update-service --cluster "$ECS_CLUSTER_NAME" --service "$UI_SERVICE" --desired-count 1 --region "${REGION}" > /dev/null 2>&1 || true
    echo "   ✅ UI service scaled to 1"
fi
fi

echo ""

# =============================================================================
# Step 3: Deploy VPN Stack (VPN.yml)
# =============================================================================
if [ -z "$ONLY_STACK" ] || [ "$ONLY_STACK" = "vpn" ]; then
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[3/3] Deploying VPN Stack: ${VPN_STACK}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Get VPC from backend stack if not already fetched
if [ -z "${VPC_ID:-}" ]; then
    VPC_ID=$(get_stack_output "${BACKEND_STACK}" "VPCId")
fi

# Get public subnet for VPN
PUBLIC_SUBNET_ONE=$(get_stack_output "${BACKEND_STACK}" "PublicSubnetOneId" 2>/dev/null || echo "")

if [ -z "$PUBLIC_SUBNET_ONE" ] || [ "$PUBLIC_SUBNET_ONE" = "None" ]; then
    PUBLIC_SUBNET_ONE=$(aws cloudformation describe-stack-resource \
        --stack-name "${BACKEND_STACK}" \
        --logical-resource-id "PublicSubnetOne" \
        --region "${REGION}" \
        --query "StackResourceDetail.PhysicalResourceId" \
        --output text)
fi

echo "   VPC:             ${VPC_ID}"
echo "   Public Subnet:   ${PUBLIC_SUBNET_ONE}"

deploy_stack "${VPN_STACK}" "${SCRIPT_DIR}/VPN.yml" \
    "ParameterKey=NameBurtualHubVPN,ParameterValue=${VPN_HUB_NAME}" \
    "ParameterKey=IPsecPreSharedKey,ParameterValue=${VPN_PSK}" \
    "ParameterKey=SoftetherPassword,ParameterValue=${VPN_PASSWORD}" \
    "ParameterKey=SubnetIdPublicSoftether,ParameterValue=${PUBLIC_SUBNET_ONE}" \
    "ParameterKey=VPCId,ParameterValue=${VPC_ID}" \
    "ParameterKey=VPNUsername,ParameterValue=${VPN_USERNAME}" \
    "ParameterKey=VPNUserPassword,ParameterValue=${VPN_USER_PASSWORD}" \
    "ParameterKey=LocalDomainName,ParameterValue=${LOCAL_DOMAIN}"
fi

echo ""

# =============================================================================
# Summary
# =============================================================================
echo "=============================================="
echo " ✅ Deployment Complete!"
echo "=============================================="
echo ""

BACKEND_DNS=$(get_stack_output "${BACKEND_STACK}" "LoadBalancerDNS" 2>/dev/null || echo "pending")
UI_URL=$(get_stack_output "${UI_STACK}" "LoadBalancerURL" 2>/dev/null || echo "pending")
VPN_IP=$(get_stack_output "${VPN_STACK}" "IPSoftether" 2>/dev/null || echo "pending")
OVPN_S3=$(get_stack_output "${VPN_STACK}" "OpenVPNConfigS3" 2>/dev/null || echo "pending")

echo " Backend API:"
echo "   ALB:   ${BACKEND_URL}"
echo "   DNS:   api.${LOCAL_DOMAIN}"
echo ""
echo " UI:"
echo "   ALB:   ${UI_URL}"
echo "   DNS:   ui.${LOCAL_DOMAIN}"
echo ""
echo " VPN:"
echo "   IP:    ${VPN_IP}"
echo "   Hub:   ${VPN_HUB_NAME}"
echo "   User:  ${VPN_USERNAME}"
echo ""
echo " OpenVPN Config:"
echo "   Download: aws s3 cp ${OVPN_S3} ./modtester-vpn.ovpn"
echo ""
echo " Credentials:"
echo "   Web:   ${UI_USERNAME:-admin} / ${DEMO_PASSWORD}"
echo "   VPN:   ${VPN_USERNAME:-modtester} / (as configured)"
echo ""
echo " Next Steps:"
echo "   1. Download OpenVPN config:"
echo "      aws s3 cp ${OVPN_S3} ./modtester-vpn.ovpn"
echo "   2. Import into OpenVPN client and connect"
echo "      (Username: ${VPN_USERNAME}, Password: as configured)"
echo "   3. Open UI: https://ui.${LOCAL_DOMAIN} or ${UI_URL}"
echo "=============================================="
