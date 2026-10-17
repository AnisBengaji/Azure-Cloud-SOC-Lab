#!/usr/bin/env bash
#
# attacks.sh — Adversary emulation runbook
# Cloud SOC Lab · 8 techniques across 6 MITRE ATT&CK tactics
#
# Each attack is run from the attacker host (Kali) against resources in the
# dedicated attack resource group. Techniques are reproduced manually via
# Azure CLI (Stratus Red Team's Azure modules were blocked by the student
# subscription's region policy — see README "Engineering Notes").
#
# WARNING: run only against your own subscription / lab resources.
# Set these first:
SUB="<SUBSCRIPTION_ID>"
RG="rg-attack-exfil"
REGION="francecentral"


# =====================================================================
# T1530 — Data from Cloud Storage (Collection)
# Expose a storage account to anonymous public access.
# =====================================================================
ACCT="anisdemo$RANDOM"
az storage account create -n "$ACCT" -g "$RG" -l "$REGION" \
  --sku Standard_LRS --kind StorageV2 --allow-blob-public-access false
# THE ATTACK:
az storage account update -n "$ACCT" -g "$RG" --allow-blob-public-access true


# =====================================================================
# T1562.008 — Disable Cloud Logs (Defense Evasion)
# Delete the subscription diagnostic setting that feeds the SIEM.
# (Recreated immediately afterward to restore the logging pipeline.)
# =====================================================================
az monitor diagnostic-settings subscription delete --name send-to-sentinel --yes
# restore:
az monitor diagnostic-settings subscription create \
  --name send-to-sentinel --location "$REGION" \
  --workspace "/subscriptions/$SUB/resourceGroups/rg-cloudsoc-lab/providers/Microsoft.OperationalInsights/workspaces/law-cloudsoc" \
  --logs '[{"category":"Administrative","enabled":true},{"category":"Security","enabled":true},{"category":"Policy","enabled":true},{"category":"Alert","enabled":true}]'


# =====================================================================
# T1562 — Impair Defenses / Network Exposure (Defense Evasion)
# Open management ports (SSH/RDP) to the internet via an NSG rule.
# =====================================================================
az network nsg create --name nsg-attack -g "$RG" -l "$REGION"
# THE ATTACK:
az network nsg rule create --name allow-ssh-from-internet \
  --nsg-name nsg-attack -g "$RG" --priority 100 \
  --direction Inbound --access Allow --protocol Tcp \
  --destination-port-ranges 22 3389 --source-address-prefixes "0.0.0.0/0"


# =====================================================================
# T1562 — Impair Defenses / Defender (Defense Evasion)
# Downgrade a Microsoft Defender for Cloud plan to disable protection.
# =====================================================================
az security pricing create -n StorageAccounts --tier Standard
# THE ATTACK (turn protection off):
az security pricing create -n StorageAccounts --tier Free


# =====================================================================
# T1098 — Account Manipulation (Persistence)
# Create an RBAC role assignment (own account, Reader — safe).
# =====================================================================
MY_ID=$(az ad signed-in-user show --query id -o tsv)
# THE ATTACK:
az role assignment create --assignee "$MY_ID" --role "Reader" \
  --scope "/subscriptions/$SUB/resourceGroups/$RG"


# =====================================================================
# T1485 — Data Destruction (Impact) · resource lock
# Delete a resource lock to remove protection against destructive actions.
# =====================================================================
az lock create --name protect-lock -g "$RG" --lock-type CanNotDelete
# THE ATTACK:
az lock delete --name protect-lock -g "$RG"


# =====================================================================
# T1485 — Data Destruction (Impact) · blob deletion
# Delete blob data (soft-delete enabled so recovery can be demonstrated).
# NOTE: requires per-account blob diagnostic logging (StorageDelete) to be
# captured in Sentinel — see README "Engineering Notes".
# =====================================================================
BACCT="anisimpact$RANDOM"
az storage account create -n "$BACCT" -g "$RG" -l "$REGION" \
  --sku Standard_LRS --kind StorageV2 \
  --allow-blob-public-access true --allow-shared-key-access true
az storage account blob-service-properties update -n "$BACCT" -g "$RG" \
  --enable-delete-retention true --delete-retention-days 7
BKEY=$(az storage account keys list -n "$BACCT" -g "$RG" --query "[0].value" -o tsv)
az storage container create --name victim-data --account-name "$BACCT" --account-key "$BKEY"
echo "important business records" > critical.txt
az storage blob upload --account-name "$BACCT" --container-name victim-data \
  --name critical.txt --file critical.txt --account-key "$BKEY" --overwrite
# THE ATTACK:
az storage blob delete --account-name "$BACCT" --container-name victim-data \
  --name critical.txt --account-key "$BKEY"


# =====================================================================
# T1552 — Unsecured Credentials (Credential Access)
# Read secrets from Key Vault (requires AuditEvent diagnostic logging).
# =====================================================================
VAULT="anisvault$RANDOM"
az keyvault create --name "$VAULT" -g "$RG" -l "$REGION"
MY_ID=$(az ad signed-in-user show --query id -o tsv)
az role assignment create --assignee "$MY_ID" --role "Key Vault Secrets Officer" \
  --scope "/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.KeyVault/vaults/$VAULT"
sleep 30
az keyvault secret set --vault-name "$VAULT" --name "db-admin-password" --value "FakeP@ssw0rd"
# THE ATTACK (credential harvesting):
az keyvault secret show --vault-name "$VAULT" --name "db-admin-password" --query value -o tsv



# ---------------------------------------------------------------------
