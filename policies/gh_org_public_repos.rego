package compliance_framework.public_repos

_checks["repos"] if {
	input.settings.public_repos > 0
}

_checks["gists"] if {
	input.settings.public_gists > 0
}

violation[{}] if {
	some check in _checks
}


title := "No Public Repos or Gists"
description := "The Organization should not have any public repositories or gists attached to it"
