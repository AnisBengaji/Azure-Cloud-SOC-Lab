# Azure Cloud SOC Lab

A home lab where I built a small Security Operations Center on Azure and Microsoft Sentinel: I run attacks against my own subscription, detect them, and in a couple of cases remediate them automatically.

I built it to learn cloud detection hands-on. Everything (detections, playbooks, hardening) is committed as code so it can be re-deployed.

## Architecture

```
  Kali (Azure CLI)
        │  runs attack techniques
        ▼
  Azure subscription  ──►  Activity Log, Key Vault & Storage diagnostic logs
  (rg-attack-exfil)              │
                                 ▼
                      Log Analytics workspace (law-cloudsoc)
                                 │
                                 ▼
                      Microsoft Sentinel  ──►  9 analytics rules → incidents
                                 │
                   ┌─────────────┴─────────────┐
                   ▼                           ▼
          Logic App playbooks           Discord channel
          (auto-remediation)            (alerts)
```

>  ![Architecture](docs/architecture.svg)

## What's in it

- **8 attack techniques** run from a Kali box with the Azure CLI, covering 6 MITRE ATT&CK tactics.
- **9 Sentinel analytics rules** written in KQL and deployed as ARM templates, including one correlation rule that only fires when the same identity does several things in a short window.
- **2 auto-remediation playbooks** (Logic Apps): one disables public access on an exposed storage account, one deletes an NSG rule that opens a port to the internet. Both run in under a minute and post to a Discord channel.
- **A hardening pass** on the storage accounts, checked before and after with Prowler against the CIS Azure benchmark.

## Detection coverage

| Technique | Tactic | Detection | Auto-remediated |
|-----------|--------|-----------|-----------------|
| T1530 public storage exposure | Collection | yes | yes |
| T1562 NSG opens port to internet | Defense Evasion | yes | yes |
| T1562.008 diagnostic setting deleted | Defense Evasion | yes | — |
| T1562 Defender plan disabled | Defense Evasion | yes | — |
| T1098 role assignment | Persistence | yes | — |
| T1485 resource lock deleted | Impact | yes | — |
| T1485 blob deleted | Impact | yes | — |
| T1552 Key Vault secret read | Credential Access | yes | — |

Only the clearly-malicious, easily-reversible actions are auto-remediated. The rest alert for review, since auto-reverting something like a role assignment could break legitimate access.

## Prerequisites

- An Azure subscription (I used Azure for Students). Owner or Contributor + User Access Administrator on the resource group, so you can deploy rules, create playbooks, and assign roles.
- Microsoft Sentinel enabled on a Log Analytics workspace, with the subscription Activity Log streamed to it.
- Azure CLI and Prowler installed on the attacker host (Kali here).
- A Discord webhook if you want the alerts (optional).

## Deployment

The detections and automation are ARM templates, deployed with the Azure CLI:

```bash
# deploy one detection rule
az deployment group create \
  --resource-group rg-cloudsoc-lab \
  --template-file detections/01-storage-public-exposure-T1530.json

# deploy a playbook
az deployment group create \
  --resource-group rg-cloudsoc-lab \
  --template-file playbooks/storage-containment.json
```

Before deploying, replace the placeholders (`<SUBSCRIPTION_ID>`, `<TENANT_ID>`, `<YOUR_DISCORD_WEBHOOK>`, `<PLAYBOOK_TRIGGER_URL>`) with your own values. The rule names reference the workspace `law-cloudsoc` — change that if yours differs.

Hardening and attacks are shell scripts; read them before running and edit the account/resource names to match your environment.

## Safety

Everything here attacks resources I created in my own subscription, inside a dedicated resource group. Run these simulations only against resources you own or are explicitly authorized to test. The attack scripts create their own targets; don't point them at anything you don't control. The scripts also leave the subscription in a deliberately weak state (that's what the detections catch) — clean up or re-harden afterward.

## A few things I ran into

- I started with Stratus Red Team to detonate the Azure techniques, but its detonations kept failing with a region error. Stratus deploys to East US by default, which my student subscription's region policy blocks, and the `AZURE_DEFAULT_REGION` variable only applies to AWS. I used its technique catalog as a reference and reproduced each attack manually with the Azure CLI, which also gave me tighter control over what each one logged.
- Key Vault secret reads and blob deletes don't show up in the Activity Log. They're data-plane events, so I had to turn on diagnostic logging on those resources to catch them.
- After hardening a storage account with `default-action Deny`, a later attack against it was blocked outright, which was a nice reminder that prevention and detection work together.

## Repo layout

```
detections/   9 Sentinel rules (ARM templates)
playbooks/    Logic App playbooks
automation/   rules linking detections to playbooks
hardening/    storage hardening script
attacks/      the attack commands
reports/      Prowler before/after
docs/         notes and screenshots
```

## Tools

Microsoft Sentinel, Azure Monitor / Log Analytics, KQL, Defender for Cloud, Azure Logic Apps, Stratus Red Team (reference), Prowler, Azure CLI, Kali Linux.

---

Anis Bengaji — cybersecurity student, SOC / detection focus.
