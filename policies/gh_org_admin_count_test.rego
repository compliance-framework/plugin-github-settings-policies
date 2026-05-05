package compliance_framework.admin_count

test_admin_count_compliant if {
    count(violation) == 0 with input as {
        "owners": [
            {"login": "admin1"},
            {"login": "admin2"},
            {"login": "admin3"}
        ]
    }
}

test_admin_count_at_limit if {
    count(violation) == 0 with input as {
        "owners": [
            {"login": "admin1"},
            {"login": "admin2"},
            {"login": "admin3"},
            {"login": "admin4"},
            {"login": "admin5"}
        ]
    }
}

test_admin_count_exceeded if {
    count(violation) > 0 with input as {
        "owners": [
            {"login": "admin1"},
            {"login": "admin2"},
            {"login": "admin3"},
            {"login": "admin4"},
            {"login": "admin5"},
            {"login": "admin6"}
        ]
    }
}
