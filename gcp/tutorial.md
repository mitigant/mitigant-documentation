# Mitigant: GCP Attack Emulation Setup

This walkthrough provisions the least-privilege IAM role and service account
Mitigant Cloud Attack Emulation needs in your project. Takes about 2 minutes.

**Creates:** one custom IAM role, one service account, one JSON key.
All resources are named `mitigant-attack-emulation-{suffix}` for easy
identification in Cloud Audit Logs.

> **Running commands.** Each command in this walkthrough sits in a code
> block with two icons in the top-right corner. Click the left icon
> (**Copy to Cloud Shell**, terminal-prompt symbol) to paste the command
> into the terminal. The right icon (**Copy**) only copies to clipboard
> and does not run anything.

---

## Step 1: Authorize Cloud Shell

If prompted, click **Authorize** to allow Cloud Shell to call Google APIs on
your behalf. This is a standard Google prompt and is shown once per session.

---

## Step 2: Confirm your project

Run the command below to print the currently active GCP project ID:

```bash
gcloud config get-value project
```

The printed value should match the project ID shown on the Mitigant
onboarding screen. If it does not, switch the active project:

```bash
gcloud config set project YOUR_PROJECT_ID
```

---

## Step 3: Run the setup script

Run the command below, then press **Enter** in the terminal:

```bash
bash setup.sh
```

The script will:

1. Show the active project and ask you to confirm. Press **Enter** to accept.
2. Check the project for an existing service account. If one is found,
   you will be asked whether to add CAE permissions to it. Type **n** and
   press **Enter** to create a new service account instead.
3. Create the custom IAM role.
4. Create the service account and bind the role.
5. Generate and print a JSON key.

---

## Step 4: Copy the JSON key

When the script finishes it prints a JSON block between two separator lines.
Select **everything between the separators** and copy.

---

## Step 5: Return to Mitigant

Paste the JSON key into the **Service Account Key** field on the Mitigant
onboarding screen and click **Connect**.

---

Questions? Email <support@mitigant.io> or open an issue at
[github.com/mitigant/mitigant-documentation](https://github.com/mitigant/mitigant-documentation).
