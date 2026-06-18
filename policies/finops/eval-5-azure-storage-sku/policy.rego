package SentinelOneCNS

# Flags Azure Storage Accounts using geo-redundant replication (GRS or RAGRS)
# when tagged as a dev or test environment.
#
# FinOps rationale: geo-redundant storage tiers (Standard_GRS, Standard_RAGRS)
# cost roughly twice as much as locally-redundant storage. Paying for
# geo-redundancy on non-production data is wasteful. Resources tagged
# environment=dev or environment=test should use a cheaper tier such as
# Standard_LRS or Standard_ZRS instead.
#
# Input fields read:
#   input.sku.name   : the SKU tier of the storage account (e.g. "Standard_GRS")
#   input.tags       : an object whose keys are tag names and values are tag values

import future.keywords.in

geo_redundant_skus := {"standard_grs", "standard_ragrs"}

non_prod_env_values := {"dev", "test"}

# Returns true if any tag key matches "environment" (case-insensitive)
# and its value is "dev" or "test" (case-insensitive).
has_non_prod_env_tag {
    some key in object.keys(input.tags)
    lower(key) == "environment"
    lower(input.tags[key]) in non_prod_env_values
}

isVulnerable {
    lower(input.sku.name) in geo_redundant_skus
    has_non_prod_env_tag
}

context := {
    "sku": input.sku.name,
    "tags": input.tags,
}
