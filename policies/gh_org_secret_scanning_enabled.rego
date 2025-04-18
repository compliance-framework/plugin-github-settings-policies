package compliance_framework.secret_scanning

violation[{}] if {
    input.secret_scanning_enabled_for_new_repositories == false
}

title := "Secret Scanning is enabled for new repositories in the organization"
description := "All new repositories should be set up for secret scanning as the default."
remarks := "Endpoint is closing down at some point and moving to code security configurations: See https://docs.github.com/rest/code-security/configurations"

controls := [
    # OWASP DSOMM v3
    # https://dsomm.owasp.org/
    # Class: OWASP_DSOMM_3
    #
    # TV: Test and Verification
    {
        "class": "SAMA_CSF_1.0",
        "control-id": "TV-6.8",  # Test for stored secrets https://dsomm.owasp.org/activity-description?uuid=c6e3c812-56e2-41b0-ae01-b7afc41a004c&dimension=Test%20and%20Verification&subDimension=Static%20depth%20for%20infrastructure&level=1&activityName=Test%20for%20stored%20secrets

        "statement-ids": [
            "TV-6.8_statement"
        ]
    },
    {
        "class": "SP800-218",
        "control-id": "RV-1.1"
    },
    {
        "class": "SP800-218",
        "control-id": "PW-1.3"
    },
    {
        "class": "SP800-218",
        "control-id": "PW-5.1"
    },
    {
        "class": "SP800-218",
        "control-id": "PW-8.2"
    },
    {
        "class": "OWASP_DSOMM_3",
        "control-id": "IG-2.5",
    },
    {
        "class": "OWASP_DSOMM_3",
        "control-id": "TV-6.8",
    },
]