package compliance_framework.web_commit_signoff

test_web_commit_signoff_required if {
    count(violation) == 0 with input as {
        "settings": {
            "web_commit_signoff_required": true
        }
    }
}

test_web_commit_signoff_not_required if {
    count(violation) > 0 with input as {
        "settings": {
            "web_commit_signoff_required": false
        }
    }
}
