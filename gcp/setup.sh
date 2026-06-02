#!/bin/bash
# Mitigant CAE — GCP Onboarding Script
# Repository: https://github.com/mitigant/mitigant-documentation/tree/main/gcp
#
# This script creates a least-privilege custom IAM role, a dedicated
# service account, and a JSON key for Mitigant Cloud Attack Emulation.
#
# Attack execution and safety architecture:
# https://mitigant.io/en/blog/cloud-attack-emulation-101-shallow-waters#attack-methodology-design-for-safety
#
# Prerequisites: run inside Google Cloud Shell, authenticated to
# the Google account that has Owner or IAM Admin access to the target project.

set -euo pipefail

# ── Helpers ───────────────────────────────────────────────────────────────────

generate_suffix() {
  LC_ALL=C tr -dc 'a-z0-9' < /dev/urandom | head -c 4
}

# GCP project IDs: lowercase letters, numbers, hyphens; 6-30 chars; must start
# and end with a letter or number. Validate before touching any GCP resource.
validate_project_id() {
  local id="$1"
  if [[ ! "$id" =~ ^[a-z0-9][a-z0-9-]{4,28}[a-z0-9]$ ]]; then
    echo "Error: '$id' is not a valid GCP Project ID."
    echo "       Must be 6-30 characters, lowercase letters, numbers and hyphens only,"
    echo "       and must start and end with a letter or number."
    exit 1
  fi
}

# ── Suffix generation ─────────────────────────────────────────────────────────
# A unique 4-character lowercase alphanumeric suffix is appended to every
# resource name so that multiple onboarding runs on the same project never
# collide. Keep a record of the suffix shown at the end in case you need to
# identify or remove these resources later.
#
# GCP naming constraints applied:
#   SA_NAME   : lowercase letters, numbers, hyphens (6-30 chars)
#   ROLE_NAME : letters, numbers, underscores only — no hyphens (3-64 chars)
#   KEY_FILE  : local filename only, no GCP constraint

SUFFIX=$(generate_suffix)

# SA_NAME  : hyphens allowed, 30-char GCP max.
#            "mitigant-attack-emulation" = 25 chars + "-" + 4-char suffix = 30 exactly.
#            This is the value that appears in Cloud Audit Logs as principalEmail —
#            customers filter on it to isolate Mitigant attack activity from real traffic.
#
# ROLE_NAME: GCP role IDs do not allow hyphens — underscores used instead.
#            Mirrors the AWS "Mitigant-Attack-Emulation" role naming convention.
#
# KEY_FILE : local filename only, no GCP constraint.

SA_NAME="mitigant-attack-emulation-${SUFFIX}"
ROLE_NAME="mitigant_attack_emulation_${SUFFIX}"
KEY_FILE="mitigant-attack-emulation-${SUFFIX}-key.json"

# ── Permissions ───────────────────────────────────────────────────────────────

PERMISSIONS=(
  resourcemanager.projects.get
  resourcemanager.projects.getIamPolicy
  resourcemanager.projects.setIamPolicy
  iam.serviceAccounts.get
  iam.serviceAccounts.list
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
  storage.buckets.list
  storage.buckets.getIamPolicy
  storage.buckets.setIamPolicy
  storage.buckets.update
  storage.objects.get
  storage.objects.list
  secretmanager.secrets.get
  secretmanager.secrets.list
  secretmanager.versions.access
)

PERMISSIONS_CSV=$(IFS=,; echo "${PERMISSIONS[*]}")

# ── Step 1: confirm project ───────────────────────────────────────────────────

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Mitigant CAE — GCP Onboarding"
echo "  Run ID: $SUFFIX"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# PROJECT_ID can be pre-set by the Mitigant onboarding button via cloudshell_command.
# If it is, skip the interactive prompt entirely.

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

echo ""
echo "Project  : $PROJECT_ID"
echo "Role     : $ROLE_NAME"
echo "Account  : $SA_NAME"
echo "Key file : $KEY_FILE"
echo ""

# ── Step 2: create custom role ────────────────────────────────────────────────

echo "Creating custom role..."
echo ""

gcloud iam roles create "$ROLE_NAME" \
  --project="$PROJECT_ID" \
  --title="Mitigant Attack Emulation" \
  --description="Least-privilege role for Mitigant Attack Emulation (run $SUFFIX)" \
  --stage=GA \
  --permissions="$PERMISSIONS_CSV" \
  --quiet

echo "Role created: projects/$PROJECT_ID/roles/$ROLE_NAME"
echo ""

# ── Step 3: create service account ───────────────────────────────────────────

echo "Creating service account..."
echo ""

SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

gcloud iam service-accounts create "$SA_NAME" \
  --project="$PROJECT_ID" \
  --display-name="Mitigant Attack Emulation" \
  --quiet

echo "Service account created: $SA_EMAIL"
echo ""

# ── Step 4: bind role to service account ─────────────────────────────────────

echo "Binding role to service account..."
echo ""

gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="projects/${PROJECT_ID}/roles/${ROLE_NAME}" \
  --quiet

echo "Role bound."
echo ""

# ── Step 5: create JSON key ───────────────────────────────────────────────────

echo "Generating JSON key..."
echo ""

gcloud iam service-accounts keys create "$KEY_FILE" \
  --iam-account="$SA_EMAIL" \
  --quiet

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Setup complete.  Run ID: $SUFFIX"
echo ""
echo "  Resources created in project: $PROJECT_ID"
echo "    Role    : projects/$PROJECT_ID/roles/$ROLE_NAME"
echo "    Account : $SA_EMAIL"
echo ""
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
