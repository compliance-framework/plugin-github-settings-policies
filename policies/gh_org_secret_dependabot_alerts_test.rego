package compliance_framework.dependabot_alerts

test_scanning_enabled_new_repos if {
    count(violation) == 0 with input as {
        "organization": {
            "dependabot_alerts_enabled_for_new_repositories": true
        }
    }
}

test_secret_scanning_enabled_new_repos_violate_if_disabled if {
    count(violation) > 0 with input as {
        "organization": {
            "dependabot_alerts_enabled_for_new_repositories": false
        }
    }
}