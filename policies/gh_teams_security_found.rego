package compliance_framework.teams_security_found

_team_with_security if {
    some team in input.teams
    contains(team.name, "security")
}

_team_with_security if {
    some team in input.teams
    contains(team.description, "security")
}

violation[{}] if {
    not _team_with_security
}

title := "Security Teams are present within Github"
description := "A dedicated security team should be created in the organization to manage security-related tasks and incidents, as well as provide consulting when required."
