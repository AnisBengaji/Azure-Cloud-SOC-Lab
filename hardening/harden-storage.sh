#!/usr/bin/env bash
#
# harden-storage.sh
# Storage-account hardening as code, applied after the CSPM baseline scan.
# Remediates the high-severity CIS findings surfaced by Prowler, including the
# exploited public-exposure finding (T1530).
#
# Validated with a second Prowler scan: storage checks passed rose from 6 to 18.
#
# Usage: edit the variables, then: bash harden-storage.sh
set -euo pipefail

# --- Target accounts (edit to your own) ---
ACCT_A="anisexfil20415"
RG_A="rg-attack-exfil"
ACCT_B="anistest230713"
RG_B="rg-storagetest2"

harden () {
  local ACCT="$1" RG="$2"
  echo "=== Hardening ${ACCT} in ${RG} ==="

  # Disable anonymous public blob access (fixes the exploited T1530 finding)
  az storage account update -n "$ACCT" -g "$RG" --allow-blob-public-access false

  # Default network action = Deny (no implicit internet reachability)
  az storage account update -n "$ACCT" -g "$RG" --default-action Deny

  # Disable Shared Key auth -> force Microsoft Entra ID (RBAC) auth
  az storage account update -n "$ACCT" -g "$RG" --allow-shared-key-access false

  # Enforce TLS 1.2 minimum
  az storage account update -n "$ACCT" -g "$RG" --min-tls-version TLS1_2

  # Data-protection: blob versioning + soft delete (blob and container)
  az storage account blob-service-properties update -n "$ACCT" -g "$RG" \
    --enable-versioning true \
    --enable-delete-retention true --delete-retention-days 7 \
    --enable-container-delete-retention true --container-delete-retention-days 7

  echo "=== Done: ${ACCT} ==="
}

harden "$ACCT_A" "$RG_A"
harden "$ACCT_B" "$RG_B"

echo
echo "Re-scan to validate:"
echo "  prowler azure --az-cli-auth --service storage --output-formats html \\"
echo "    --output-filename prowler-afterhardening-\$(date +%Y%m%d)"
