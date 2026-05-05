package compliance_framework.default_repo_permission

test_default_permission_read if {
    count(violation) == 0 with input as {
        "settings": {
            "default_repository_permission": "read"
        }
    }
}

test_default_permission_none if {
    count(violation) == 0 with input as {
        "settings": {
            "default_repository_permission": "none"
        }
    }
}

test_default_permission_write if {
    count(violation) > 0 with input as {
        "settings": {
            "default_repository_permission": "write"
        }
    }
}

test_default_permission_admin if {
    count(violation) > 0 with input as {
        "settings": {
            "default_repository_permission": "admin"
        }
    }
}
