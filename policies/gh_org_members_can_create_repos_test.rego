package compliance_framework.members_can_create_repos

test_members_cannot_create_repos if {
    count(violation) == 0 with input as {
        "settings": {
            "members_can_create_repositories": false
        }
    }
}

test_members_can_create_repos if {
    count(violation) > 0 with input as {
        "settings": {
            "members_can_create_repositories": true
        }
    }
}
