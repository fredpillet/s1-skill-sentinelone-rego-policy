# Cloud-specific Rego Patterns for SentinelOneCNS

This file contains real patterns drawn from production policies. Read the section for the relevant cloud provider before writing a policy.

---

## AWS

### Input schema conventions
AWS input objects mirror the raw AWS API response for each resource type. Common shapes:

**Security Group:**
```json
{
  "GroupId": "sg-abc123",
  "IpPermissions": [
    {
      "IpProtocol": "tcp",
      "FromPort": 3306,
      "ToPort": 3306,
      "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
      "Ipv6Ranges": [{"CidrIpv6": "::/0"}]
    }
  ],
  "Tags": [{"Key": "Name", "Value": "rds-sg"}]
}
```

**S3 Bucket Policy:**
```json
{
  "PolicyDocument": {
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": "*",
        "Action": "*",
        "Resource": "arn:aws:s3:::my-bucket/*"
      }
    ]
  }
}
```

**IAM effective permissions (Lambda, EC2 role, etc.):**
```json
{
  "effectivePermissions": {
    "statement": [/* array of IAM statement objects */]
  }
}
```

### Pattern: check open ports to the world
```rego
package SentinelOneCNS

# Flags security groups that allow inbound TCP access to risky database ports
# from the public internet (0.0.0.0/0 or ::/0).

risky_ports := {3306, 5432, 1433, 1521, 6379, 9200}

public_risky_port_access {
    some i
    perm := input.IpPermissions[i]
    perm.IpProtocol == "tcp"
    perm.FromPort == perm.ToPort
    risky_ports[perm.FromPort]
    ip_range_contains_world(perm.IpRanges)
}

ip_range_contains_world(ipranges) {
    ipranges != null
    some j
    ipranges[j].CidrIp == "0.0.0.0/0"
}

isVulnerable {
    input.GroupId != ""
    public_risky_port_access
}
```

### Pattern: S3 bucket policy with wildcard principal + action
```rego
package SentinelOneCNS

# Flags S3 bucket policies that grant full access (*) to any principal (*).

is_public_principal(principal) { principal == "*" }
is_public_principal(principal) {
    some key
    principal[key] == "*"
}

is_full_access(action) { action == "*" }
is_full_access(action) {
    some i
    action[i] == "*"
}

isVulnerable {
    some statement
    stmt := input.PolicyDocument.Statement[statement]
    stmt.Effect == "Allow"
    is_public_principal(stmt.Principal)
    is_full_access(stmt.Action)
}
```

### Pattern: IAM action allowlist check with context
```rego
package SentinelOneCNS
import future.keywords.in

# Flags resources whose effective IAM permissions include any of the listed actions.

dangerous_actions := {
    "s3:PutObjectRetention",
    "s3:PutLifecycleConfiguration",
    "s3:PutBucketPolicy",
    "s3:PutBucketVersioning"
}

isVulnerable {
    hasAnyActionAllowed(input.effectivePermissions.statement, dangerous_actions)
}

context := {
    "vulnerableActions": getVulnerableActions(input.effectivePermissions.statement, dangerous_actions)
}
```
> Note: `hasAnyActionAllowed` and `getVulnerableActions` are helper functions expected to be provided by the engine's standard library. Use them by name when the check is action-based.

### Tips for AWS
- Always handle both `IpRanges` (IPv4) and `Ipv6Ranges` (IPv6) when checking for public access
- Tag checks: iterate `input.Tags[t]` and use `lower()` on both key and value for case-insensitive matching
- Use `input.GroupId != ""` as a guard to ensure the input is actually a security group

---

## Azure

### Input schema conventions
Azure input objects follow the ARM (Azure Resource Manager) structure. All resource-specific data lives under `input.properties`. Diagnostic settings, addon profiles, and linked resources may appear as top-level keys alongside `properties`.

**Virtual Machine / VMSS:**
```json
{
  "properties": {
    "virtualMachineProfile": {
      "diagnosticsProfile": {
        "bootDiagnostics": {"enabled": true}
      }
    }
  }
}
```

**AKS Cluster:**
```json
{
  "properties": {
    "addonProfiles": {
      "omsAgent": {
        "enabled": true,
        "config": {"logAnalyticsWorkspaceResourceID": "/subscriptions/..."}
      }
    }
  }
}
```

**Diagnostic settings (attached resource):**
```json
{
  "firewallDiagnosticSetting": [
    {
      "properties": {
        "logs": [{"enabled": true}],
        "storageAccountId": "/subscriptions/...",
        "workspaceId": "/subscriptions/..."
      }
    }
  ]
}
```

### Pattern: default true, override to false (safe if condition met)
Use when a resource is vulnerable unless a specific feature is explicitly enabled.

```rego
package SentinelOneCNS

# Flags VMs where boot diagnostics is not enabled.

default isVulnerable = false

isVulnerable = false {
    not input.properties
} else = false {
    input.properties.virtualMachineProfile.diagnosticsProfile.bootDiagnostics.enabled == true
} else = true {
    true
}
```

> The `else` chain is the idiomatic Azure pattern. OPA evaluates each branch in order; the first one that evaluates to a defined value wins.

### Pattern: diagnostic settings check with multiple valid destinations
```rego
package SentinelOneCNS

# Flags Azure Firewalls that have no diagnostic settings, or have settings
# with no logs enabled, or have settings with no valid log destination.
# All conditions are consolidated into a single isVulnerable rule via helpers.

default isVulnerable = false

hasDiagnosticSettings {
    count(input.firewallDiagnosticSetting) > 0
}

logsEnabled {
    setting := input.firewallDiagnosticSetting[_]
    logs := setting.properties.logs[_]
    logs.enabled == true
}

hasLogDestination {
    setting := input.firewallDiagnosticSetting[_]
    setting.properties.storageAccountId
}
hasLogDestination {
    setting := input.firewallDiagnosticSetting[_]
    setting.properties.workspaceId
}
hasLogDestination {
    setting := input.firewallDiagnosticSetting[_]
    setting.properties.eventHubAuthorizationRuleId
}
hasLogDestination {
    setting := input.firewallDiagnosticSetting[_]
    setting.properties.marketplacePartnerId
}

misconfigured {
    not hasDiagnosticSettings
}
misconfigured {
    hasDiagnosticSettings
    not logsEnabled
}
misconfigured {
    hasDiagnosticSettings
    not hasLogDestination
}

isVulnerable {
    misconfigured
}
```

### Pattern: check two possible field names (API inconsistency)
```rego
package SentinelOneCNS

# AKS: Container Insights not enabled.
# Handles both 'omsAgent' and 'omsagent' property name variants.

default isVulnerable = true

isVulnerable = false {
    input.properties.addonProfiles.omsAgent.enabled
    input.properties.addonProfiles.omsAgent.config.logAnalyticsWorkspaceResourceID
} {
    input.properties.addonProfiles.omsagent.enabled
    input.properties.addonProfiles.omsagent.config.logAnalyticsWorkspaceResourceID
}
```

### Tips for Azure
- Always guard with `not input.properties` when `properties` could be absent; a missing field makes rules undefined (falsy), which with `default isVulnerable = true` means the resource would be flagged even if it's just missing data
- Multiple `isVulnerable` rules are OR-ed together — use this to check several failure conditions cleanly
- Prefer `else` chains when you need sequential fallback logic; prefer multiple rule heads for independent OR conditions

---

## GCP

### Input schema conventions
GCP input objects follow the GCP REST API structure. The `kind` field identifies the resource type.

**Cloud Storage Bucket:**
```json
{
  "kind": "storage#bucket",
  "name": "my-bucket",
  "encryption": {
    "defaultKmsKeyName": "projects/my-project/locations/us/keyRings/..."
  }
}
```

**Compute Instance:**
```json
{
  "name": "my-vm",
  "canIpForward": false,
  "zone": "https://www.googleapis.com/compute/v1/projects/my-project/zones/us-central1-a"
}
```

**Cloud Armor Security Policy:**
```json
{
  "rules": [
    {
      "priority": 1000,
      "action": "deny(403)",
      "match": {
        "expr": {
          "expression": "evaluatePreconfiguredExpr('cve-canary')"
        }
      }
    }
  ]
}
```

### Pattern: flag when a field is absent (encryption not configured)
```rego
package SentinelOneCNS

# Flags GCP Storage buckets where customer-managed encryption (CMEK) is not configured.

isVulnerable {
    input.kind == "storage#bucket"
    not input.encryption.defaultKmsKeyName
}
```

### Pattern: regex match on a field value
```rego
package SentinelOneCNS

# Flags Cloud Armor policies missing a deny rule for the cve-canary WAF expression.

default isVulnerable = true

isVulnerable = false {
    regex.match("^evaluatePreconfiguredExpr\\('cve-canary'", input.rules[i].match.expr.expression)
    regex.match("^deny", input.rules[i].action)
}
```

### Pattern: use context to surface structured metadata
```rego
package SentinelOneCNS

# Flags Compute instances with IP forwarding enabled (except GKE nodes).

isVulnerable = false {
    startswith(input.name, "gke-")
} else = true {
    input.canIpForward == true
}

getZone := split(input.zone, "/")

context := {
    "zone": getZone[8],
    "gcpProjectId": getZone[6]
}
```

### Tips for GCP
- Use `input.kind` as a guard when you want to assert the resource type
- `split(url, "/")` is the idiomatic way to extract project ID and zone from GCP self-link URLs
- GKE-managed resources typically have names starting with `gke-` — exclude them from checks that don't apply to managed nodes
- `not input.field.subfield` is safe in GCP rules: if the field is missing, the condition is true (resource is vulnerable), which is usually what you want for "feature not configured" checks
