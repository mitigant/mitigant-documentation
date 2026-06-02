# Mitigant Documentation

Public resources for Mitigant platform setup and integrations.

## Contents

| Directory | Description |
|-----------|-------------|
| [`gcp/`](./gcp/) | GCP onboarding for Cloud Attack Emulation |

---

## GCP — Cloud Attack Emulation

Run the setup script via the Mitigant onboarding screen, or manually in Cloud Shell:

```bash
git clone https://github.com/mitigant/mitigant-documentation.git
cd mitigant-documentation/gcp
PROJECT_ID=your-project-id bash setup.sh
```

The script creates a least-privilege custom IAM role, a dedicated service account,
and a JSON key. All resources are named `mitigant-attack-emulation-{suffix}` for
easy identification in Cloud Audit Logs.

For attack execution and safety architecture, see the
[Mitigant blog](https://mitigant.io/en/blog/cloud-attack-emulation-101-shallow-waters#attack-methodology-design-for-safety).
