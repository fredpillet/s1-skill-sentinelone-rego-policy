package SentinelOneCNS

# Detects AWS EBS volumes that are unattached (state == "available").
#
# FinOps context: EBS volumes in "available" state are not attached to any EC2 instance
# but continue to accrue storage charges. Identifying and deleting or snapshotting these
# volumes reduces unnecessary cloud spend.
#
# Input: a single EBS Volume object from the AWS DescribeVolumes API response
# (i.e., one element of the Volumes array returned by DescribeVolumes).
#
# Key fields read:
#   input.VolumeId  : unique identifier for the volume (used as a guard)
#   input.State     : lifecycle state; "available" means unattached, "in-use" means attached
#
# A volume is vulnerable (flagged) when its State is "available".
# Volumes in "in-use", "creating", "deleting", "deleted", or "error" states are not flagged.

isVulnerable {
    input.VolumeId != ""
    input.State == "available"
}

context := {
    "volumeId":         input.VolumeId,
    "state":            input.State,
    "availabilityZone": input.AvailabilityZone,
    "sizeGiB":          input.Size,
    "volumeType":       input.VolumeType,
}
