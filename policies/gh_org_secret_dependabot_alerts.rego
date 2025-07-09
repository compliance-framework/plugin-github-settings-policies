package compliance_framework.dependabot_alerts

violation[{}] if {
    input.dependabot_alerts_enabled_for_new_repositories == false
}

title := "Dependabot alerts enabled for new repositories"
description := "All new repositories should be set up to alert for any dependabot alerts that are coming from the repositories"
remarks := "Endpoint is closing down at some point and moving to code security configurations: See https://docs.github.com/rest/code-security/configurations"
