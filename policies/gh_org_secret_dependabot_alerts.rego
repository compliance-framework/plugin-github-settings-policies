package compliance_framework.dependabot_alerts

violation[{}] if {
    input.dependabot_alerts_enabled_for_new_repositories == false
}

title := "Dependabot alerts enabled for new repositories"
description := "All new repositories should be set up to alert for any dependabot alerts that are coming from the repositories"
remarks := "Endpoint is closing down at some point and moving to code security configurations: See https://docs.github.com/rest/code-security/configurations"

controls := [
    {
        "class": "SP800-53-enhancement",
        "control-id": "ra-5.4",  # Discoverable Information
    },
    {
        "class": "SP800-218",
        "control-id": "RV-1.1",
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
        "control-id": "IG-3.3",
    },
    {
        "class": "OWASP_DSOMM_3",
        "control-id": "IG-3.4",
    },
    {
        "class": "OWASP_DSOMM_3",
        "control-id": "IG-2.5",
    },
    {
        "class": "OWASP_DSOMM_3",
        "control-id": "TV-6.3",
    },
]
