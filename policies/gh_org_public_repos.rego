package compliance_framework.public_repos

checks["repos"] if {
	input.public_repos > 0
}

checks["gists"] if {
	input.public_gists > 0
}

violation[{}] if {
	some check in checks
}


title := "No Public Repos or Gists"
description := "The Organization should not have any public repositories or gists attached to it"

# No direct controls in the frameworks at the moment
# But will be useful when we are mapping ISO 27001, data privacy or custom 
# IPR frameworks generated either as a standard or a custom catalog
controls := []
