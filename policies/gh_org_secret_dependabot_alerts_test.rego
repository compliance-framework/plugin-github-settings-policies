package compliance_framework.dependabot_alerts

test_pass_when_all_default_config_has_dependabot_alerts_enabled if {
    count(violation) == 0 with input as {
        "default_security_configs": [
            {
                "default_for_new_repos": "all",
                "configuration": {
                    "name": "Baseline Security Profile",
                    "dependabot_alerts": "enabled"
                }
            }
        ]
    }
}

test_pass_when_public_and_private_internal_configs_have_dependabot_alerts_enabled if {
    count(violation) == 0 with input as {
        "default_security_configs": [
            {
                "default_for_new_repos": "public",
                "configuration": {
                    "name": "Baseline Security Profile",
                    "dependabot_alerts": "enabled"
                }
            },
            {
                "default_for_new_repos": "private_and_internal",
                "configuration": {
                    "name": "Private Repos Profile",
                    "dependabot_alerts": "enabled"
                }
            }
        ]
    }
}

test_violate_when_only_public_config_has_dependabot_alerts_enabled if {
    count(violation) > 0 with input as {
        "default_security_configs": [
            {
                "default_for_new_repos": "public",
                "configuration": {
                    "name": "Baseline Security Profile",
                    "dependabot_alerts": "enabled"
                }
            }
        ]
    }
}

test_violate_when_private_internal_config_has_dependabot_alerts_disabled if {
    count(violation) > 0 with input as {
        "default_security_configs": [
            {
                "default_for_new_repos": "public",
                "configuration": {
                    "name": "Baseline Security Profile",
                    "dependabot_alerts": "enabled"
                }
            },
            {
                "default_for_new_repos": "private_and_internal",
                "configuration": {
                    "name": "Private Repos Profile",
                    "dependabot_alerts": "disabled"
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

test_violate_when_default_configs_missing if {
    count(violation) > 0 with input as {}
}

test_violate_when_all_configs_have_dependabot_alerts_disabled if {
    count(violation) > 0 with input as {
        "default_security_configs": [
            {
                "default_for_new_repos": "public",
                "configuration": {
                    "name": "Baseline Security Profile",
                    "dependabot_alerts": "disabled"
                }
            }
        ]
    }
}

test_violate_when_all_configs_have_dependabot_alerts_not_set if {
    count(violation) > 0 with input as {
        "default_security_configs": [
            {
                "default_for_new_repos": "public",
                "configuration": {
                    "name": "Baseline Security Profile",
                    "dependabot_alerts": "not_set"
                }
            }
        ]
    }
}
