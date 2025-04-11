package compliance_framework.mfa_enabled

test_mfa_enabled if {
    count(violation) == 0 with input as {
        "organization": {
            "two_factor_requirement_enabled": true
        }
    }
}

test_mfa_violate_if_disabled if {
    count(violation) > 0 with input as {
        "organization": {
            "two_factor_requirement_enabled": false
        }
    }
}