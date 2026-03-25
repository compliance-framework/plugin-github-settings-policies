package compliance_framework.teams_security_found

risk_templates := [
  {
    "name": "No dedicated security team exists in the organization",
    "title": "Absence of Security Team Leaves No Clear Ownership for Security Incidents and Risk",
    "statement": "Without a dedicated security team in the GitHub organization, there is no identifiable group responsible for managing security incidents, reviewing security-sensitive code changes, enforcing security policies, or providing guidance to developers. This creates an accountability gap where security concerns may go unaddressed, vulnerabilities remain untracked, and incident response is ad hoc and slow.",
    "likelihood_hint": "moderate",
    "impact_hint": "high",
    "violation_ids": ["no_security_team"],
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-657",
        "title": "Violation of Secure Design Principles",
        "url": "https://cwe.mitre.org/data/definitions/657.html"
      },
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-693",
        "title": "Protection Mechanism Failure",
        "url": "https://cwe.mitre.org/data/definitions/693.html"
      }
    ],
    "remediation": {
      "title": "Create a dedicated security team in the GitHub organization",
      "description": "Establish a named security team in the GitHub organization with defined membership, responsibilities, and CODEOWNERS entries for security-sensitive paths. The team should be the designated point of contact for security incidents, vulnerability disclosures, and security policy enforcement.",
      "tasks": [
        { "title": "Create a GitHub team with 'security' in the name (e.g., 'Security', 'security-ops', 'AppSec')" },
        { "title": "Assign appropriate members with security responsibilities to the team" },
        { "title": "Set the team to 'closed' visibility to limit exposure of membership" },
        { "title": "Add the security team as a CODEOWNER for security-sensitive paths (e.g., auth, infra, CI configs)" },
        { "title": "Document the team's responsibilities in the organization's security policy or SECURITY.md" },
        { "title": "Configure GitHub to route security advisories and vulnerability reports to the security team" }
      ]
    }
  }
]

_team_with_security if {
    some team in input.teams
    contains(lower(team.name), "security")
}

_team_with_security if {
    some team in input.teams
    contains(lower(team.description), "security")
}

violation[{"id": "no_security_team"}] if {
    not _team_with_security
}

title := "Security Teams are present within Github"
description := "A dedicated security team should be created in the organization to manage security-related tasks and incidents, as well as provide consulting when required."
