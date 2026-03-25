package compliance_framework.teams_privacy_closed

risk_templates := [
  {
    "name": "Organization team is not set to closed visibility",
    "title": "Non-Standard Team Visibility Undermines Organizational Auditability and Governance",
    "statement": "GitHub teams not set to 'closed' visibility deviate from the organization's standard access control posture. Teams set to 'secret' are invisible to other organization members, which can hide privileged groups from security audits, obscure access control structures, and create shadow administrative boundaries that are difficult to govern. Standardizing all teams on 'closed' visibility ensures that team membership is transparent to organization members while remaining hidden from external actors, enabling consistent security review and access control governance.",
    "likelihood_hint": "moderate",
    "impact_hint": "moderate",
    "violation_ids": ["team_not_closed"],
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-778",
        "title": "Insufficient Logging",
        "url": "https://cwe.mitre.org/data/definitions/778.html"
      },
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-284",
        "title": "Improper Access Control",
        "url": "https://cwe.mitre.org/data/definitions/284.html"
      }
    ],
    "remediation": {
      "title": "Set all organization teams to closed (private) visibility",
      "description": "Configure every GitHub team in the organization to use 'closed' visibility so that team membership is only visible to organization members, reducing exposure of internal organizational structure.",
      "tasks": [
        { "title": "Audit all teams in the organization and identify those not set to 'closed' visibility" },
        { "title": "Update each non-closed team's privacy setting to 'closed' via the GitHub team settings page or API" },
        { "title": "Establish a policy requiring all new teams to be created with 'closed' visibility" },
        { "title": "Automate team visibility auditing using this policy on a scheduled basis" }
      ]
    }
  }
]

violation[{"id": "team_not_closed"}] if {
    some team in input.teams
    team.privacy != "closed"
}

title := "All teams are private within the organization"
description := "All teams within the organization must be set to private to ensure sensitive information is not exposed."