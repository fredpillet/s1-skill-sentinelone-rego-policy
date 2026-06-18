---
name: s1-rego-policy
description: >
  Generate SentinelOne CSPM-compliant Rego policies (OPA v0.68) for the SentinelOneCNS engine.
  Use this skill whenever a user asks to write, create, build, or generate a Rego policy, CSPM rule,
  or cloud security check for SentinelOne's CSPM engine — even if they just describe the security
  condition in plain language (e.g., "write a rule that flags S3 buckets without encryption",
  "create a check for Azure VMs without boot diagnostics", "build a GCP policy for public IPs").
  Also trigger when the user says "rego", "OPA policy", "SentinelOneCNS", "CSPM rule", or
  "isVulnerable". If the user describes a cloud misconfiguration they want to detect, use this skill.
---

# SentinelOne CSPM Rego Policy Generator

You are generating Rego policies for SentinelOne's CSPM engine (OPA v0.68). Every policy you write must conform to the conventions below — they are non-negotiable because the engine evaluates these fields by name.

## Hard requirements

1. **Package**: always `package SentinelOneCNS`
2. **No em dash (`—`) anywhere in the file** — not in comments, not in strings. The S1 OPA engine does not handle this character and will break. Use `:` or `-` instead.
2. **Required output**: `isVulnerable` — a boolean that is `true` when the resource is misconfigured
3. **OPA version**: v0.68. Use `import future.keywords.in` only when you use `in` keyword expressions; omit it otherwise
4. **No external imports** beyond `future.keywords.in` and `future.keywords.every` if needed
5. **Optional output**: a `context` object — use it to surface useful metadata (e.g., zone, project ID, resource name, vulnerable field values) that helps responders understand the finding

## Workflow

### Step 1 — Gather intent

If the user hasn't fully specified what they want, ask:
- **What is the misconfiguration?** (e.g., "S3 bucket allows public read", "VM missing encryption at rest")
- **Cloud provider?** (AWS / Azure / GCP) — if not stated and not obvious from resource names, ask
- **Resource type?** (e.g., Security Group, Storage Account, Compute Instance) — infer from context when possible; ask if ambiguous
- **Any specific conditions?** (e.g., "only flag if tagged as production", "only when port 22 is open from 0.0.0.0/0")

If the intent is clear enough, proceed directly to writing the policy and explain your assumptions in a brief comment at the top.

### Step 2 — Write the policy

Follow the patterns in `references/patterns.md` for the appropriate cloud. Key guidance:

**Single `isVulnerable` rule — no exceptions.**
Never define more than one `isVulnerable` rule head. All detection logic must live in a single rule. Use helper rules to keep it readable, but the entry point is always one `isVulnerable`.

When you have multiple independent failure conditions, extract them into named helper rules and combine them in the single `isVulnerable`:
```rego
# Good
no_logs { not hasDiagnosticSettings }
logs_disabled { hasDiagnosticSettings; not logsEnabled }

isVulnerable { no_logs }        # ← still two heads
```
No — even this is two heads. Do it like this instead:
```rego
misconfigured {
    not hasDiagnosticSettings
}
misconfigured {
    hasDiagnosticSettings
    not logsEnabled
}

isVulnerable { misconfigured }  # ← single entry point
```

**Choose the right logic polarity:**
- If a resource is vulnerable by default and only safe if a specific condition is met → use `default isVulnerable = true` with a single `isVulnerable = false { ... }` override
- If a resource is safe by default and only vulnerable when something is wrong → use a single `isVulnerable { ... }` rule, using helper rules for complex sub-conditions

**Structure:**
```
package SentinelOneCNS

# Optional: import future.keywords.in

# Optional: default
# default isVulnerable = false

# Helper rules / functions (before main rule, clearly named)

# Main rule
isVulnerable { ... }

# Optional: context
context := { ... }
```

**Iteration:**
- Use `some i` with explicit index when you need the index value
- Use `_` wildcard (`input.array[_]`) for anonymous iteration
- Use `some key` for object key iteration

**String operations available:** `lower()`, `upper()`, `contains()`, `startswith()`, `endswith()`, `split()`, `trim()`, `regex.match()`, `regex.find_all_string_submatch_n()`

**Array/set operations:** `count()`, `any()`, `all()` (via `every`), set literals `{val1, val2}`

### Step 3 — Validate and annotate

After writing the policy:
1. Add a **comment block at the top** (after the package declaration) describing what the rule detects and why it matters
2. Double-check: does `isVulnerable` evaluate to `true` only when the resource is genuinely misconfigured?
3. Check edge cases: what happens if the relevant field is `null` or missing? OPA treats undefined as falsy in `{ }` rule bodies — make sure this behaves correctly for your polarity
4. If the policy uses `context`, confirm the fields are derivable from `input` (no hallucinated fields)

### Step 4 — Deliver

Output the policy as a code block. Then provide two minimal JSON samples the user can paste into a file and validate locally:

```bash
# Syntax check
opa check policy.rego

# Evaluate against a sample input
opa eval -d policy.rego -i input.json 'data.SentinelOneCNS.isVulnerable'
```

The two samples to include:
- **Vulnerable input** — a realistic JSON object that should return `true`
- **Safe input** — a realistic JSON object that should return `false`

Use actual field names and value formats from the cloud provider's API (see `references/patterns.md`). Don't use placeholder values.

Also briefly explain:
- What the policy detects
- Which `input` fields it reads
- Any assumptions about the input schema
- Edge cases handled or not handled

If you're uncertain about the input schema for a resource type, say so and propose an assumption the user can confirm.

## Reference

Read `references/patterns.md` for cloud-specific examples and input schema conventions.
