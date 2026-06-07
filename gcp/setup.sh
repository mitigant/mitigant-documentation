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
  # TODO: restore when api.mitigant.io/onboarding/gcp endpoint is live.
  # Only fires for production runs (MTG_ENV=production set by the Mitigant frontend).
  # Dev and manual runs are silent. Backend URL is hardcoded -- never pass it
  # via cloudshell_command as that would expose it in the browser address bar.
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

ERROR_LOG=$(mktemp)
CURRENT_STAGE="init"

# ── Partial failure cleanup ───────────────────────────────────────────────────

cleanup() {
  local error_msg=""
  [[ -f "$ERROR_LOG" ]] && error_msg=$(head -3 "$ERROR_LOG" | tr '\n' ' ')
  echo ""
  echo "Setup failed at stage: ${CURRENT_STAGE}"
  [[ -n "$error_msg" ]] && echo "Reason: $error_msg"
  echo ""
  call_home "failure" "${CURRENT_STAGE}|${error_msg}"
  echo "Cleaning up partial resources..."
  # Only delete the SA if we created it. In the existing-CSPM flow the SA
  # belonged to the customer before this run; never delete it.
  if [[ -z "${EXISTING_CSPM_SA_EMAIL:-}" ]]; then
    gcloud iam service-accounts delete "${SA_EMAIL:-placeholder@placeholder.com}" \
      --quiet 2>/dev/null || true
  fi
  gcloud iam roles delete "$ROLE_NAME" \
    --project="${PROJECT_ID:-}" --quiet 2>/dev/null || true
  rm -f "$ERROR_LOG"
}
trap cleanup ERR

# ── Permissions ───────────────────────────────────────────────────────────────

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
  logging.sinks.list
  logging.sinks.get
  logging.sinks.create
  logging.sinks.delete
)

# ── Step 1: confirm project ───────────────────────────────────────────────────

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Mitigant CAE -- GCP Onboarding"
echo "  Run ID: $SUFFIX"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# PROJECT_ID resolution order:
#   1. Environment variable (set directly, e.g. legacy cloudshell_command usage)
#   2. Temp file written by cloudshell_command from the Mitigant onboarding button
#   3. Interactive prompt (fallback for manual runs)

if [[ -n "${PROJECT_ID:-}" ]]; then
  echo "Project ID received from Mitigant: $PROJECT_ID"
  validate_project_id "$PROJECT_ID"
  gcloud config set project "$PROJECT_ID" --quiet
elif [[ -f /tmp/.mtg_project_id ]]; then
  PROJECT_ID=$(tr -d '[:space:]' < /tmp/.mtg_project_id)
  rm -f /tmp/.mtg_project_id
  echo "Project ID loaded from Mitigant: $PROJECT_ID"
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

# ── Step 1c: existing Mitigant CSPM service account check ───────────────────
# When this project is already onboarded to Mitigant for CSPM, the customer
# has a service account here that the FE shows on the onboarding screen.
# We prefer adding CAE permissions to that existing SA over creating a new
# one -- one Mitigant SA per project keeps the IAM footprint clean and the
# existing CSPM JSON key continues to work.

CURRENT_STAGE="existing_account_check"
echo ""
echo "If you already onboarded this project to Mitigant for CSPM, we can"
echo "add CAE permissions to that existing service account instead of"
echo "creating a new one. The email is shown on the Mitigant onboarding"
echo "screen with a Copy button next to it."
echo ""
read -r -p "Existing Mitigant CSPM service account email (press Enter to create new): " EXISTING_CSPM_SA_EMAIL
EXISTING_CSPM_SA_EMAIL=$(echo "${EXISTING_CSPM_SA_EMAIL:-}" | tr -d '[:space:]')

if [[ -n "$EXISTING_CSPM_SA_EMAIL" ]]; then
  if ! gcloud iam service-accounts describe "$EXISTING_CSPM_SA_EMAIL" \
      --project="$PROJECT_ID" --quiet > /dev/null 2>"$ERROR_LOG"; then
    error_detail=$(head -2 "$ERROR_LOG" | tr '\n' ' ')
    echo ""
    echo "Error: service account '$EXISTING_CSPM_SA_EMAIL' not found in project '$PROJECT_ID'."
    [[ -n "$error_detail" ]] && echo "       Detail: $error_detail"
    exit 1
  fi
  SA_EMAIL="$EXISTING_CSPM_SA_EMAIL"
  echo "Existing CSPM service account confirmed: $SA_EMAIL"
  echo ""
fi

echo ""
echo "Project  : $PROJECT_ID"
echo "Role     : $ROLE_NAME"
if [[ -n "${EXISTING_CSPM_SA_EMAIL:-}" ]]; then
  echo "Account  : $SA_EMAIL (existing, CAE permissions will be added)"
else
  echo "Account  : $SA_NAME (new)"
  echo "Key file : $KEY_FILE"
fi
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
# Skipped in the existing-CSPM flow -- SA_EMAIL was set during the existing
# account check above.

if [[ -z "${EXISTING_CSPM_SA_EMAIL:-}" ]]; then
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

  # GCP IAM is eventually consistent. Poll until the SA is accessible before binding.
  echo "Waiting for service account to propagate..."
  for i in 1 2 3 4 5 6; do
    if gcloud iam service-accounts describe "$SA_EMAIL" \
        --project="$PROJECT_ID" --quiet > /dev/null 2>&1; then
      break
    fi
    if [[ $i -eq 6 ]]; then
      echo "Service account did not propagate in time. Please re-run the script."
      exit 1
    fi
    echo "  Not yet available, retrying in 5s ($i/6)..."
    sleep 5
  done
  echo ""
fi

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

# resourcemanager.tagBindings.list is not grantable in custom roles, only via
# the predefined roles/resourcemanager.tagViewer. Bind it separately so the
# tag-based exemption filter can read tag bindings on individual resources
# during attack target resolution.
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/resourcemanager.tagViewer" \
  --condition=None \
  --quiet > /dev/null 2>"$ERROR_LOG"

echo "Role bound."
echo ""

# ── Step 5: create JSON key ───────────────────────────────────────────────────
# Skipped in the existing-CSPM flow -- the SA already has a key that the
# customer uploaded during CSPM onboarding; that same key gains CAE access
# once the new role is bound.

if [[ -z "${EXISTING_CSPM_SA_EMAIL:-}" ]]; then
  CURRENT_STAGE="key_create"
  echo "Generating JSON key..."
  echo ""

  gcloud iam service-accounts keys create "$KEY_FILE" \
    --iam-account="$SA_EMAIL" \
    --quiet 2>"$ERROR_LOG"
fi

rm -f "$ERROR_LOG"
call_home "success"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Setup complete.  Run ID: $SUFFIX"
echo ""
if [[ -n "${EXISTING_CSPM_SA_EMAIL:-}" ]]; then
  echo "  Updated resources in project: $PROJECT_ID"
  echo "    Role    : projects/$PROJECT_ID/roles/$ROLE_NAME (new)"
  echo "    Account : $SA_EMAIL (existing, CAE permissions added)"
else
  echo "  Resources created in project: $PROJECT_ID"
  echo "    Role    : projects/$PROJECT_ID/roles/$ROLE_NAME"
  echo "    Account : $SA_EMAIL"
fi
echo ""
if [[ ${#MISSING_PERMS[@]} -gt 0 ]]; then
  echo "  Note: ${#MISSING_PERMS[@]} permission(s) were unavailable and excluded"
  echo "  from the role. Affected attacks will be skipped at runtime."
  echo ""
fi
if [[ -n "${EXISTING_CSPM_SA_EMAIL:-}" ]]; then
  echo "  CAE permissions have been added to your existing service account."
  echo "  Return to Mitigant and click Connect (or Enable CAE)."
  echo "  Your existing CSPM key now has CAE permissions; no new key needed."
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
else
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
fi
