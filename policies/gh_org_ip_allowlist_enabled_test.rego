package compliance_framework.ip_allowlist_enabled

test_ip_allowlist_configured if {
    count(violation) == 0 with input as {
        "ip_allow_list": [
            {"allow_list_value": "203.0.113.0/24", "is_active": true, "name": "Office"},
            {"allow_list_value": "198.51.100.0/24", "is_active": false, "name": "Old VPN"}
        ]
    }
}

test_ip_allowlist_all_inactive if {
    count(violation) > 0 with input as {
        "ip_allow_list": [
            {"allow_list_value": "203.0.113.0/24", "is_active": false, "name": "Disabled"},
            {"allow_list_value": "198.51.100.0/24", "is_active": false, "name": "Also Disabled"}
        ]
    }
}

test_ip_allowlist_empty if {
    count(violation) > 0 with input as {
        "ip_allow_list": []
    }
}
