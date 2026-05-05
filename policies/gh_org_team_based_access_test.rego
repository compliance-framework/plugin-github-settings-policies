package compliance_framework.team_based_access

test_teams_present if {
    count(violation) == 0 with input as {
        "teams": [
            {"name": "developers", "privacy": "closed"},
            {"name": "security", "privacy": "closed"}
        ]
    }
}

test_no_teams if {
    count(violation) > 0 with input as {
        "teams": []
    }
}
