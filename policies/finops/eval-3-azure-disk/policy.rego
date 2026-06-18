package SentinelOneCNS

# Flags Azure Managed Disks that are not attached to any virtual machine.
#
# An unattached managed disk continues to accrue storage cost without providing
# value, making it an orphaned resource from a FinOps perspective.
#
# input.properties.diskState possible values:
#   "Attached"      : disk is in use by a VM (safe)
#   "Unattached"    : disk exists but is not mounted to any VM (vulnerable)
#   "Reserved"      : disk is reserved but not actively attached (vulnerable)
#   "ActiveSAS"     : disk is exported via SAS URL, not attached to a VM (vulnerable)
#   "ReadyToUpload" : disk is being prepared for upload (vulnerable)
#   "ActiveUpload"  : disk is actively being uploaded (vulnerable)
#
# Field read: input.properties.diskState

default isVulnerable = false

isVulnerable = false {
    not input.properties
} else = false {
    input.properties.diskState == "Attached"
} else = true {
    true
}

context := {
    "diskState": input.properties.diskState,
    "diskName":  input.name,
    "location":  input.location,
    "sku":       input.sku.name,
}
