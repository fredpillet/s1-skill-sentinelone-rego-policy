package SentinelOneCNS

# Flags GCP Persistent Disks that are not attached to any VM instance.
#
# Unattached persistent disks continue to incur storage charges even though
# no workload is using them (FinOps: wasted spend). A disk is considered
# unattached when input.users is null, absent, or an empty array.
#
# Input: a single GCP Compute Disk object from the Compute Engine API
#   (https://cloud.google.com/compute/docs/reference/rest/v1/disks/get)
#
# Key fields read:
#   input.users       : array of resource URLs of instances using this disk
#   input.type        : self-link URL of the disk type (e.g. pd-ssd, pd-balanced)
#   input.zone        : self-link URL of the zone the disk lives in
#   input.name        : disk resource name
#   input.kind        : should be "compute#disk"

default isVulnerable = true

# Safe only when at least one VM is referencing this disk
isVulnerable = false {
    count(input.users) > 0
}

# Extract the last path segment from a GCP self-link URL.
# e.g. "https://.../zones/us-central1-a" -> index [8] -> "us-central1-a"
# We split on "/" and take the last element regardless of URL depth.
getZoneParts := split(input.zone, "/")
getTypeParts := split(input.type, "/")

context := {
    "diskName": input.name,
    "diskType": getTypeParts[count(getTypeParts) - 1],
    "zone":     getZoneParts[count(getZoneParts) - 1],
}
