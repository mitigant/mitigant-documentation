# Mitigant: Enable CAE on an existing CSPM account

This walkthrough adds Cloud Attack Emulation (CAE) permissions to your
existing Mitigant CSPM service account in this project. Takes about 1 minute.

**Modifies:** creates one custom IAM role and binds it (plus
`roles/resourcemanager.tagViewer`) to your existing Mitigant CSPM service
account. No new service account is created, and no new JSON key is
generated. Your existing CSPM key gains CAE access once the role is bound.

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
2. Ask for your existing Mitigant CSPM service account email. On the
   Mitigant onboarding screen, click the **Copy** button next to the
   service account email, then paste it into the terminal and press **Enter**.
3. Create the custom IAM role with CAE permissions.
4. Bind the role to your existing CSPM service account.

No new service account is created. No new JSON key is needed.

---

## Step 4: Return to Mitigant

When the script finishes, return to Mitigant and click **Connect**
(or **Enable CAE**) on the onboarding screen. Your existing CSPM key
already has CAE permissions through the role we just bound.

---

Questions? Email <support@mitigant.io> or open an issue at
[github.com/mitigant/mitigant-documentation](https://github.com/mitigant/mitigant-documentation).
