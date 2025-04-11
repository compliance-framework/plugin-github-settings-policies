package compliance_framework.public_repos

test_public_repos_is_zero if {
    count(violation) == 0 with input as {
        "organization": {
            "pubic_repos": 0,
            "public_gists": 0
        }
    }
}

test_public_repos_violate_when_higher if {
    count(violation) > 0 with input as {
        "organization": {
            "public_repos": 10,
            "public_gists": 0
        }
    }
}