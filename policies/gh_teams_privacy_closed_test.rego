package compliance_framework.teams_privacy_closed

test_teams_privacy_closed if {
    count(violation) == 0 with input as {
        "teams": [
            {
                "name": "team1",
                "privacy": "closed"
            },
            {
                "name": "team2",
                "privacy": "closed"
            }
        ]
    }
}

test_teams_privacy_open if {
    count(violation) > 0 with input as {
        "teams": [
            {
                "name": "team1",
                "privacy": "open"
            },
            {
                "name": "team2",
                "privacy": "closed"
            }
        ]
    }
}
