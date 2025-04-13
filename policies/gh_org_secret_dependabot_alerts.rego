package compliance_framework.dependabot_alerts

violation[{}] if {
    input.dependabot_alerts_enabled_for_new_repositories == false
}

title := "Dependabot alerts enabled for new repositories"
description := "All new repositories should be set up to alert for any dependabot alerts that are coming from the repositories"
remarks := "Endpoint is closing down at some point and moving to code security configurations: See https://docs.github.com/rest/code-security/configurations"

controls := [
    {
        "class": "SP800-53",
        "control-id": "ra-5.4",  # Discoverable Information
        "statement-ids": []
    },
    {
        "class": "SP800-218",
        "control_id": "RV-1.1",
        "statement-ids": []
    },
    {
        "class": "OWASP_DSOMM_3",
        "control_id": "IG-3.3",
        "statement-ids": []
    },
]