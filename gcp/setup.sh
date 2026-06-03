#!/bin/bash
# Mitigant CAE -- GCP Onboarding Script
# Repository: https://github.com/mitigant/mitigant-documentation/tree/main/gcp
#
# This script creates a least-privilege custom IAM role, a dedicated
# service account, and a JSON key for Mitigant Cloud Attack Emulation.
#
# Attack execution and safety architecture:
# https://mitigant.io/en/blog/cloud-attack-emulation-101-shallow-waters#attack-methodology-design-for-safety
#
# Telemetry: this script sends run status (run ID, project ID, stage, timestamp)
# to Mitigant to enable proactive onboarding support. No credentials or
# sensitive data are transmitted. To opt out: export MITIGANT_NO_TELEMETRY=1
#
# Prerequisites: run inside Google Cloud Shell, authenticated to
# the Google account that has Owner or IAM Admin access to the target project.

set -euo pipefail

# ── Helpers ───────────────────────────────────────────────────────────────────

generate_suffix() {
  openssl rand -hex 2
}

validate_project_id() {
  local id="$1"
  if [[ ! "$id" =~ ^[a-z0-9][a-z0-9-]{4,28}[a-z0-9]$ ]]; then
    echo "Error: '$id' is not a valid GCP Project ID."
    echo "       Must be 6-30 characters, lowercase letters, numbers and hyphens only,"
    echo "       and must start and end with a letter or number."
    exit 1
  fi
}

call_home() {
  local stage="$1"
  local payload="${2:-}"
  [[ "${MITIGANT_NO_TELEMETRY:-0}" == "1" ]] && return 0
  curl -sf -X POST "https://api.mitigant.io/onboarding/gcp" \
    -H "Content-Type: application/json" \
    -d "{\"run_id\":\"${SUFFIX:-unknown}\",\"project_id\":\"${PROJECT_ID:-unknown}\",\"stage\":\"${stage}\",\"detail\":\"${payload}\",\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" \
    --max-time 5 > /dev/null 2>&1 || true
}

attack_group() {
  # Maps a permission to the attack(s) it covers, for warning output.
  case "$1" in
    iam.serviceAccounts.create|iam.serviceAccounts.delete|\
    iam.serviceAccounts.getIamPolicy|iam.serviceAccounts.setIamPolicy|\
    iam.serviceAccounts.getAccessToken|\
    iam.serviceAccountKeys.create|iam.serviceAccountKeys.delete)
      echo "IAM privilege escalation attacks" ;;
    resourcemanager.projects.setIamPolicy|resourcemanager.projects.getIamPolicy)
      echo "Project IAM backdoor / Invite External User" ;;
    compute.subnetworks.update)
      echo "Disable VPC Flow Logs" ;;
    storage.buckets.setIamPolicy|storage.buckets.update)
      echo "Public GCS Bucket / Disable Bucket Logging" ;;
    storage.objects.get|storage.objects.list)
      echo "GCS Object Exfiltration" ;;
    secretmanager.secrets.get|secretmanager.secrets.list|\
    secretmanager.versions.access)
      echo "Malicious Secret Retrieval" ;;
    *)
      echo "CSPM detection" ;;
  esac
}

# ── Suffix and resource names ─────────────────────────────────────────────────
# A unique 4-character suffix prevents collisions across multiple runs.
#
# SA_NAME   : hyphens allowed, 30-char GCP max.
#             Appears in Cloud Audit Logs as principalEmail -- customers filter
#             on "mitigant-attack-emulation" to isolate attack traffic.
# ROLE_NAME : GCP role IDs forbid hyphens, underscores used instead.
#             Mirrors the AWS "Mitigant-Attack-Emulation" naming convention.
# KEY_FILE  : local filename only, no GCP constraint.

SUFFIX=$(generate_suffix)
SA_NAME="mitigant-attack-emulation-${SUFFIX}"
ROLE_NAME="mitigant_attack_emulation_${SUFFIX}"
KEY_FILE="mitigant-attack-emulation-${SUFFIX}-key.json"

# Captures gcloud stderr for error telemetry without breaking set -e.
ERROR_LOG=$(mktemp)

# Tracks the current step so the cleanup trap can report it precisely.
CURRENT_STAGE="init"

# ── Partial failure cleanup ───────────────────────────────────────────────────
# Fires on any unhandled error. Reports the failure, calls home, then removes
# any resources created before the failure.

cleanup() {
  local error_msg=""
  [[ -f "$ERROR_LOG" ]] && error_msg=$(head -3 "$ERROR_LOG" | tr '\n' ' ')
  echo ""
  echo "Setup failed at stage: ${CURRENT_STAGE}"
  [[ -n "$error_msg" ]] && echo "Reason: $error_msg"
  echo ""
  call_home "failure" "${CURRENT_STAGE}|${error_msg}"
  echo "Cleaning up partial resources..."
  gcloud iam service-accounts delete "${SA_EMAIL:-placeholder@placeholder.com}" \
    --quiet 2>/dev/null || true
  gcloud iam roles delete "$ROLE_NAME" \
    --project="${PROJECT_ID:-}" --quiet 2>/dev/null || true
  rm -f "$ERROR_LOG"
}
trap cleanup ERR

# ── Permissions ───────────────────────────────────────────────────────────────
# DETECTION  : read-only, validated at connect time by RequiredPermissionsCheck.
# VERIFICATION: write, used during attack execution.

PERMISSIONS=(
  resourcemanager.projects.get
  resourcemanager.projects.getIamPolicy
  iam.serviceAccounts.list
  iam.serviceAccountKeys.list
  apikeys.keys.list
  compute.instances.list
  compute.instanceGroupManagers.list
  compute.projects.get
  compute.firewalls.list
  compute.backendServices.list
  storage.buckets.list
  storage.buckets.getIamPolicy
  resourcemanager.projects.setIamPolicy
  iam.serviceAccounts.get
  iam.serviceAccounts.create
  iam.serviceAccounts.delete
  iam.serviceAccounts.getIamPolicy
  iam.serviceAccounts.setIamPolicy
  iam.serviceAccounts.getAccessToken
  iam.serviceAccountKeys.create
  iam.serviceAccountKeys.delete
  compute.subnetworks.get
  compute.subnetworks.list
  compute.subnetworks.update
  storage.buckets.get
  storage.buckets.setIamPolicy
  storage.buckets.update
  storage.objects.get
  storage.objects.list
  secretmanager.secrets.get
  secretmanager.secrets.list
  secretmanager.versions.access
)

# ── Step 1: confirm project ───────────────────────────────────────────────────

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Mitigant CAE -- GCP Onboarding"
echo "  Run ID: $SUFFIX"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if [[ -n "${PROJECT_ID:-}" ]]; then
  echo "Project ID received from Mitigant: $PROJECT_ID"
  validate_project_id "$PROJECT_ID"
  gcloud config set project "$PROJECT_ID" --quiet
else
  CURRENT_PROJECT=$(gcloud config get-value project 2>/dev/null || true)
  if [[ -n "$CURRENT_PROJECT" ]]; then
    echo "Active project: $CURRENT_PROJECT"
    echo ""
    read -r -p "Is this the correct project? [y/N]: " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
      PROJECT_ID="$CURRENT_PROJECT"
    else
      read -r -p "Enter the Project ID to use: " PROJECT_ID
    fi
  else
    read -r -p "Enter your GCP Project ID: " PROJECT_ID
  fi
  validate_project_id "$PROJECT_ID"
  gcloud config set project "$PROJECT_ID" --quiet
fi

# ── Step 1a: verify project is accessible ────────────────────────────────────

CURRENT_STAGE="project_check"
echo ""
echo "Verifying project access..."

if ! gcloud projects describe "$PROJECT_ID" --quiet > /dev/null 2>"$ERROR_LOG"; then
  error_detail=$(head -2 "$ERROR_LOG" | tr '\n' ' ')
  echo ""
  echo "Error: cannot access project '$PROJECT_ID'."
  echo "       Ensure the project exists and your Google account has access."
  [[ -n "$error_detail" ]] && echo "       Detail: $error_detail"
  exit 1
fi

# ── Step 1b: probe available permissions ─────────────────────────────────────
# Uses testIamPermissions to find the subset of desired permissions the caller
# actually has. GCP only allows a role to contain permissions the creator holds,
# so this determines what the custom role can include.
# Callers with partial permissions onboard with reduced attack coverage rather
# than failing outright. Missing attacks are reported clearly.

CURRENT_STAGE="permission_probe"
echo ""
echo "Checking available permissions..."

TOKEN=$(gcloud auth print-access-token 2>/dev/null)

PERMS_JSON=$(python3 -c "
import json, sys
perms = '${PERMISSIONS[*]}'.split()
print(json.dumps(perms))
" 2>/dev/null)

PROBE_RESPONSE=$(curl -sf -X POST \
  "https://cloudresourcemanager.googleapis.com/v1/projects/${PROJECT_ID}:testIamPermissions" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"permissions\": $PERMS_JSON}" \
  --max-time 10 2>/dev/null) || PROBE_RESPONSE="{}"

AVAILABLE_PERMS=$(echo "$PROBE_RESPONSE" | python3 -c "
import json, sys
d = json.load(sys.stdin)
for p in d.get('permissions', []):
    print(p)
" 2>/dev/null || echo "")

# If probe returns empty (network issue, API disabled), fall back to full list.
if [[ -z "$AVAILABLE_PERMS" ]]; then
  echo "Permission probe unavailable -- proceeding with full permission set."
  PERMISSIONS_CSV=$(IFS=,; echo "${PERMISSIONS[*]}")
  MISSING_PERMS=()
else
  MISSING_PERMS=()
  for perm in "${PERMISSIONS[@]}"; do
    if ! echo "$AVAILABLE_PERMS" | grep -qx "$perm"; then
      MISSING_PERMS+=("$perm")
    fi
  done
  PERMISSIONS_CSV=$(echo "$AVAILABLE_PERMS" | tr '\n' ',' | sed 's/,$//')
fi

if [[ ${#MISSING_PERMS[@]} -gt 0 ]]; then
  echo ""
  echo "Warning: ${#MISSING_PERMS[@]} permission(s) not available to your account."
  echo "The following attacks will be skipped at runtime:"
  echo ""
  for perm in "${MISSING_PERMS[@]}"; do
    printf "  %-55s %s\n" "$perm" "[$(attack_group "$perm")]"
  done
  echo ""
  echo "Onboarding will continue with available permissions."
  echo "Skipped attacks will be reported in the Mitigant dashboard."
  echo ""
  MISSING_CSV=$(IFS=,; echo "${MISSING_PERMS[*]}")
  call_home "partial_permissions" "$MISSING_CSV"
else
  echo "All permissions available."
fi

echo ""
echo "Project  : $PROJECT_ID"
echo "Role     : $ROLE_NAME"
echo "Account  : $SA_NAME"
echo "Key file : $KEY_FILE"
echo ""

call_home "start"

# ── Step 2: create custom role ────────────────────────────────────────────────

CURRENT_STAGE="role_create"
echo "Creating custom role..."
echo ""

gcloud iam roles create "$ROLE_NAME" \
  --project="$PROJECT_ID" \
  --title="Mitigant Attack Emulation" \
  --description="Least-privilege role for Mitigant Attack Emulation (run $SUFFIX)" \
  --stage=GA \
  --permissions="$PERMISSIONS_CSV" \
  --quiet 2>"$ERROR_LOG"

echo "Role created: projects/$PROJECT_ID/roles/$ROLE_NAME"
echo ""

# ── Step 3: create service account ───────────────────────────────────────────

CURRENT_STAGE="sa_create"
echo "Creating service account..."
echo ""

SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

gcloud iam service-accounts create "$SA_NAME" \
  --project="$PROJECT_ID" \
  --display-name="Mitigant Attack Emulation" \
  --quiet 2>"$ERROR_LOG"

echo "Service account created: $SA_EMAIL"
echo ""

# ── Step 4: bind role to service account ─────────────────────────────────────

CURRENT_STAGE="binding"
echo "Binding role to service account..."
echo ""

# --condition=None is required when the project IAM policy already contains
# condition-based bindings; without it gcloud refuses in non-interactive mode.
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="projects/${PROJECT_ID}/roles/${ROLE_NAME}" \
  --condition=None \
  --quiet > /dev/null 2>"$ERROR_LOG"

echo "Role bound."
echo ""

# ── Step 5: create JSON key ───────────────────────────────────────────────────

CURRENT_STAGE="key_create"
echo "Generating JSON key..."
echo ""

gcloud iam service-accounts keys create "$KEY_FILE" \
  --iam-account="$SA_EMAIL" \
  --quiet 2>"$ERROR_LOG"

rm -f "$ERROR_LOG"
call_home "success"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Setup complete.  Run ID: $SUFFIX"
echo ""
echo "  Resources created in project: $PROJECT_ID"
echo "    Role    : projects/$PROJECT_ID/roles/$ROLE_NAME"
echo "    Account : $SA_EMAIL"
echo ""
if [[ ${#MISSING_PERMS[@]} -gt 0 ]]; then
echo "  Note: ${#MISSING_PERMS[@]} permission(s) were unavailable and excluded"
echo "  from the role. Affected attacks will be skipped at runtime."
echo ""
fi
echo "  Copy the JSON below and paste it into the Mitigant"
echo "  'Service Account Key' field, then click Connect."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
cat "$KEY_FILE"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Note: the key file ($KEY_FILE) is saved in this Cloud Shell"
echo "session but will not persist after the session ends."
echo ""
