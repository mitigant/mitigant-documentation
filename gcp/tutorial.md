# Mitigant — GCP Attack Emulation Setup

This walkthrough sets up the least-privilege IAM role and service account
Mitigant Cloud Attack Emulation needs to run in your project.

**Time:** ~2 minutes
**What it creates:** one custom IAM role, one service account, one JSON key

---

## Step 1 — Authorize Cloud Shell

If prompted, click **Authorize** to allow Cloud Shell to make API calls on
your behalf. This is a standard Google prompt for any Cloud Shell session.

---

## Step 2 — Run the setup script

The script runs automatically with your project ID pre-set.
If the terminal is not already running, paste and execute:

```bash
bash setup.sh
```

The script will:

1. Confirm the target project
2. Create a `mitigant_attack_emulation_{suffix}` custom role (25 least-privilege permissions)
3. Create a `mitigant-attack-emulation-{suffix}` service account
4. Bind the role to the service account
5. Generate and print a JSON key

A unique 4-character suffix is appended to each resource name per run.
The suffix and full resource names are printed to the terminal on completion.

---

## Step 3 — Copy the JSON key

When the script finishes, it prints a JSON block between two separator lines.
Select everything between the separators and copy it.

---

## Step 4 — Return to Mitigant

Paste the JSON key into the **Service Account Key** field in Mitigant
and click **Connect**.

---

## Questions?

Open an issue at
[github.com/mitigant/mitigant-documentation](https://github.com/mitigant/mitigant-documentation)
or contact support@mitigant.io.
