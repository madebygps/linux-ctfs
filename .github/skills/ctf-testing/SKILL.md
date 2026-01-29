---
name: ctf-testing
description: Test and validate CTF challenges by deploying to AWS, Azure, or GCP. Use after modifying ctf_setup.sh, creating new challenges, or before releases to verify all 18 challenges work correctly.
---

# CTF Challenge Testing

Test CTF infrastructure by deploying to cloud providers and validating all challenges work.

## How to Use This Skill

### Step 1: Verify Prerequisites

Check these are installed and authenticated:

```bash
# Required tools
terraform --version    # >= 1.0
which sshpass          # macOS: brew install hudochenkov/sshpass/sshpass
                       # Linux: sudo apt install sshpass

# Cloud CLI (for your target provider)
aws sts get-caller-identity     # AWS
az account show                 # Azure
gcloud auth list --filter=status:ACTIVE  # GCP
```

### Step 2: Choose Test Scope

| Scenario | Command |
|----------|---------|
| Quick iteration on changes | `./deploy_and_test.sh azure` |
| Full validation before release | `./deploy_and_test.sh all` |
| Verify services survive reboot | `./deploy_and_test.sh azure --with-reboot` |

### Step 3: Run Tests

```bash
./.github/skills/ctf-testing/deploy_and_test.sh <provider> [--with-reboot]
```

Wait ~15 minutes per provider. Expected output: `RESULT: PASS (<providers>)`

### Step 4: Verify Cleanup

After tests complete (or fail), confirm no resources remain:

```bash
# AWS
aws ec2 describe-instances --filters "Name=tag:Name,Values=CTF*" "Name=instance-state-name,Values=running,pending,stopping,stopped" --query 'Reservations[*].Instances[*].[InstanceId,State.Name]' --output table

# Azure
az group list --query "[?starts_with(name, 'ctf')].name" --output table

# GCP
gcloud compute instances list --filter="name~'ctf'" --format="table(name,zone,status)"
```

If resources remain: `cd <provider> && terraform destroy -auto-approve`

## Troubleshooting

| Problem | Check |
|---------|-------|
| Setup not completing | `/var/log/setup_complete` exists? Check `/var/log/cloud-init-output.log` |
| Service not running | `systemctl status <service>` and `journalctl -u <service>` |
| SSH connection fails | Wait 3-5 min after IP available; verify security group allows port 22 |

## Scripts

- [deploy_and_test.sh](deploy_and_test.sh) - Orchestration (runs locally)
- [test_ctf_challenges.sh](test_ctf_challenges.sh) - Validation (runs on VM)
