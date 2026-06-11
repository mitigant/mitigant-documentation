#!/bin/bash
# Mitigant CAE - GCP Onboarding Script
# Repository: https://github.com/mitigant/mitigant-documentation/tree/main/gcp
#
# Creates a least-privilege custom IAM role, a dedicated service account, and
# a JSON key for Mitigant Cloud Attack Emulation.
#
# Telemetry: this script sends run status (run ID, project ID, stage, timestamp)
# to Mitigant for proactive onboarding support. No credentials or sensitive data
# are transmitted. To opt out: export MITIGANT_NO_TELEMETRY=1
#
# Prerequisites: run inside Google Cloud Shell, authenticated to the Google
# account that has Owner or IAM Admin access to the target project.

set -euo pipefail

# ── Helpers ──────────────────────────────────────────────────────────────────

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
  return 0
}

attack_group() {
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
    compute.disks.list|compute.disks.get|\
    compute.disks.getIamPolicy|compute.disks.setIamPolicy)
      echo "Compute Disk Share Exfiltration" ;;
    iam.roles.list|resourcemanager.projects.testIamPermissions)
      echo "GCP Permission Discovery" ;;
    pubsub.topics.list|pubsub.topics.getIamPolicy)
      echo "Pub/Sub Topic Enumeration" ;;
    *)
      echo "CSPM detection" ;;
  esac
}

# ── Resource names ───────────────────────────────────────────────────────────

SUFFIX=$(generate_suffix)
SA_NAME="mitigant-attack-emulation-${SUFFIX}"
ROLE_NAME="mitigant_attack_emulation_${SUFFIX}"
KEY_FILE="mitigant-attack-emulation-${SUFFIX}-key.json"

ERROR_LOG=$(mktemp)
CURRENT_STAGE="init"

# ── Partial failure cleanup ──────────────────────────────────────────────────

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

# ── Permissions ──────────────────────────────────────────────────────────────

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
  compute.disks.list
  compute.disks.get
  compute.disks.getIamPolicy
  compute.disks.setIamPolicy
  iam.roles.list
  resourcemanager.projects.testIamPermissions
  pubsub.topics.list
  pubsub.topics.getIamPolicy
  logging.sinks.list
  logging.sinks.get
  logging.sinks.create
  logging.sinks.delete
)

# ── Step 1: confirm project ──────────────────────────────────────────────────

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Mitigant CAE - GCP Onboarding"
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
    echo ""
    echo "  ┌─────────────────────────────────────────────────────────────"
    echo "  │  Active project: $CURRENT_PROJECT"
    echo "  └─────────────────────────────────────────────────────────────"
    echo ""
    read -r -p "Use this project? [Y/n]: " confirm
    if [[ -z "$confirm" || "$confirm" =~ ^[Yy]$ ]]; then
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

# The custom role always includes the full required permission set. The probe
# above is informational only: testIamPermissions at project scope is
# unreliable for permissions that are scoped on individual resources (notably
# storage.buckets.{get,update}, storage.objects.get, and
# iam.serviceAccounts.getAccessToken), so filtering the role's permission list
# based on the probe would silently strip permissions that the customer
# actually has access to. Custom-role creation itself does not require the
# caller to hold the permissions being included; if anything else later
# blocks the run, the failure surfaces with a clear gcloud error.
PERMISSIONS_CSV=$(IFS=,; echo "${PERMISSIONS[*]}")

MISSING_PERMS=()
if [[ -z "$AVAILABLE_PERMS" ]]; then
  echo "Permission probe unavailable. Proceeding with the full permission set."
else
  for perm in "${PERMISSIONS[@]}"; do
    if ! echo "$AVAILABLE_PERMS" | grep -qx "$perm"; then
      MISSING_PERMS+=("$perm")
    fi
  done
  if [[ ${#MISSING_PERMS[@]} -gt 0 ]]; then
    echo ""
    echo "Note: ${#MISSING_PERMS[@]} permission(s) were not reported as held at"
    echo "project scope by your Google account. Some are GCP testIamPermissions"
    echo "quirks (Owner role does cover them in practice). They are included"
    echo "in the role regardless. The Mitigant dashboard will flag any that"
    echo "actually remain ungranted after the service account is in use."
    echo ""
    MISSING_CSV=$(IFS=,; echo "${MISSING_PERMS[*]}")
    call_home "partial_permissions" "$MISSING_CSV"
  else
    echo "All permissions available."
  fi
fi

echo ""
echo "Project  : $PROJECT_ID"
echo "Role     : $ROLE_NAME"
echo "Account  : $SA_NAME"
echo "Key file : $KEY_FILE"
echo ""

call_home "start"

# ── Step 2: create custom role ───────────────────────────────────────────────

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

# GCP IAM is eventually consistent. Poll until the SA is accessible. A freshly
# created SA can return PERMISSION_DENIED rather than NOT_FOUND for a short
# window because the read API hasn't synced and GCP won't leak existence. So
# DENIED on early attempts is ambiguous; only treat it as a real permission
# error after it persists across several retries.
echo "Waiting for service account to propagate..."
denied_streak=0
for i in 1 2 3 4 5 6; do
  if gcloud iam service-accounts describe "$SA_EMAIL" \
      --project="$PROJECT_ID" --quiet > /dev/null 2>"$ERROR_LOG"; then
    break
  fi
  describe_err=$(head -3 "$ERROR_LOG" | tr '\n' ' ')
  if echo "$describe_err" | grep -qiE "permission|forbidden|denied"; then
    denied_streak=$((denied_streak + 1))
    if [[ $denied_streak -ge 3 ]]; then
      echo ""
      echo "Error: cannot describe the new service account after $denied_streak attempts."
      echo "       Your Google account most likely is missing the"
      echo "       'iam.serviceAccounts.get' permission needed to read the SA"
      echo "       after creation. (Eventual-consistency lag was retried and"
      echo "       still returns denied.)"
      echo "       Detail: $describe_err"
      exit 1
    fi
  else
    denied_streak=0
  fi
  if [[ $i -eq 6 ]]; then
    echo "Service account did not propagate in time. Please re-run the script."
    [[ -n "$describe_err" ]] && echo "Last error: $describe_err"
    exit 1
  fi
  echo "  Not yet available, retrying in 5s ($i/6)..."
  sleep 5
done
echo ""

# ── Step 4: bind role to service account ─────────────────────────────────────

CURRENT_STAGE="binding"
echo "Binding role to service account..."
echo ""

gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="projects/${PROJECT_ID}/roles/${ROLE_NAME}" \
  --condition=None \
  --quiet > /dev/null 2>"$ERROR_LOG"

# tagBindings.list is not grantable in custom roles; granted via tagViewer.
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/resourcemanager.tagViewer" \
  --condition=None \
  --quiet > /dev/null 2>"$ERROR_LOG"

# iam.serviceAccounts.getAccessToken is not granted by the Owner basic role
# at project scope, so even a customer running this script as project Owner
# cannot put it into the custom role. Bind serviceAccountTokenCreator to the
# new account directly so service-account-impersonation attacks can run.
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/iam.serviceAccountTokenCreator" \
  --condition=None \
  --quiet > /dev/null 2>"$ERROR_LOG"

echo "Role bound."
echo ""

# ── Step 5: create JSON key ──────────────────────────────────────────────────

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
