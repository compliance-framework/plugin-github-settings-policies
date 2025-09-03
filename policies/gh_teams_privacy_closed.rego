package compliance_framework.teams_privacy_closed

violation[{}] if {
    some team in input.teams
    team.privacy != "closed"
}

title := "All teams are private within the organization"
description := "All teams within the organization must be set to private to ensure sensitive information is not exposed."