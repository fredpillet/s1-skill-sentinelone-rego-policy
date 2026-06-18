package SentinelOneCNS

# Detects AWS Elastic IP addresses that are not associated with any running
# resource (instance or network interface). Unassociated EIPs incur a per-hour
# charge from AWS even though they are not providing value, making them a
# FinOps waste signal.
#
# Input:  a single address object from the AWS EC2 DescribeAddresses API.
# Flags:  when AssociationId is absent or null : i.e. the EIP is unattached.
#
# Fields read:
#   input.AllocationId   : used in context to identify the EIP
#   input.PublicIp       : used in context for human-readable identification
#   input.AssociationId  : primary signal: present and non-null means attached

isVulnerable {
    not input.AssociationId
}

context := {
    "allocationId": input.AllocationId,
    "publicIp": input.PublicIp,
    "reason": "Elastic IP is not associated with any instance or network interface and is incurring idle charges",
}
