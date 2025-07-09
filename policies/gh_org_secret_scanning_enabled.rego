package compliance_framework.secret_scanning

violation[{}] if {
    input.secret_scanning_enabled_for_new_repositories == false
}

title := "Secret Scanning is enabled for new repositories in the organization"
description := "All new repositories should be set up for secret scanning as the default."
remarks := "Endpoint is closing down at some point and moving to code security configurations: See https://docs.github.com/rest/code-security/configurations"
