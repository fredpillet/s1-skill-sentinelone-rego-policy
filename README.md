# sentinelone-rego-policy

A Claude skill that generates SentinelOne CSPM-compliant Rego policies for the SentinelOneCNS engine (OPA v0.68).

## What it does

Describe a cloud misconfiguration in plain language and the skill produces a ready-to-upload `policy.rego` with sample inputs for local validation.

Supports AWS, Azure, and GCP. Enforces SentinelOne-specific conventions automatically:

- `package SentinelOneCNS`
- Single `isVulnerable` boolean output
- Single rule head (no multiple `isVulnerable` definitions)
- Optional `context` object for responder metadata
- No em dash characters (breaks the S1 OPA engine)

## How to use

Install `sentinelone-rego-policy.skill` via Settings > Capabilities, then just describe what you want to detect:

> "Write a rule that flags AWS S3 buckets without versioning enabled"
> "Flag Azure VMs missing a backup policy"
> "Detect GCP Cloud SQL instances without SSL enforcement"

## Validating a policy locally

Each generated policy comes with `input_vulnerable.json` and `input_safe.json`. Run:

```bash
# Syntax check
opa check policy.rego

# Logic check
opa eval -d policy.rego -i input_vulnerable.json 'data.SentinelOneCNS.isVulnerable'
# expected: true

opa eval -d policy.rego -i input_safe.json 'data.SentinelOneCNS.isVulnerable'
# expected: false
```

## Repo structure

```
sentinelone-rego-policy/
├── skill/
│   ├── SKILL.md                  # skill instructions
│   └── references/
│       └── patterns.md           # cloud-specific Rego patterns and input schemas
├── policies/
│   ├── finops/                   # FinOps detection policies
│   │   ├── eval-1-aws-ebs/       # AWS unattached EBS volumes
│   │   ├── eval-2-aws-eip/       # AWS unassociated Elastic IPs
│   │   ├── eval-3-azure-disk/    # Azure orphaned Managed Disks
│   │   ├── eval-4-gcp-disk/      # GCP unattached Persistent Disks
│   │   └── eval-5-azure-storage-sku/  # Azure over-replicated dev storage
│   └── security/                 # Security detection policies (add yours here)
├── sentinelone-rego-policy.skill # installable skill bundle
├── .gitignore
└── README.md
```

## Contributing

Add new policies under `policies/<category>/<descriptive-name>/` with `policy.rego`, `input_vulnerable.json`, and `input_safe.json`.

To update the skill itself, edit `skill/SKILL.md` or `skill/references/patterns.md`, then repackage using the `skill-creator` skill in Cowork.

## Author

Frédéric Pillet — Cloud Security Architect, SentinelOne  
frederic.pillet@sentinelone.com
