package compliance_framework.secret_scanning

test_pass_when_default_config_has_secret_scanning_enabled if {
    count(violation) == 0 with input as {
        "default_security_configs": [
            {
                "default_for_new_repos": "public",
                "configuration": {
                    "name": "Baseline Security Profile",
                    "secret_scanning": "enabled"
                }
            }
        ]
    }
}

test_pass_when_one_of_multiple_configs_has_secret_scanning_enabled if {
    count(violation) == 0 with input as {
        "default_security_configs": [
            {
                "default_for_new_repos": "public",
                "configuration": {
                    "name": "Baseline Security Profile",
                    "secret_scanning": "enabled"
                }
            },
            {
                "default_for_new_repos": "private_and_internal",
                "configuration": {
                    "name": "Private Repos Profile",
                    "secret_scanning": "disabled"
                }
            }
        ]
    }
}

test_violate_when_no_default_configs if {
    count(violation) > 0 with input as {
        "default_security_configs": []
    }
}

test_violate_when_all_configs_have_secret_scanning_disabled if {
    count(violation) > 0 with input as {
        "default_security_configs": [
            {
                "default_for_new_repos": "public",
                "configuration": {
                    "name": "Baseline Security Profile",
                    "secret_scanning": "disabled"
                }
            }
        ]
    }
}

test_violation_includes_config_details if {
    v := violation with input as {
        "default_security_configs": [
            {
                "default_for_new_repos": "public",
                "configuration": {
                    "name": "Baseline Security Profile",
                    "secret_scanning": "disabled"
                }
            }
        ]
    }
    count(v) > 0
    v[entry]
    contains(entry.description, "Baseline Security Profile")
    contains(entry.description, "secret_scanning: disabled")
}
