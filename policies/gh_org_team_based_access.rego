package compliance_framework.team_based_access

risk_templates := [
  {
    "name": "No teams configured in the organization",
    "title": "Absence of Teams Prevents Role-Based Access Control and Access Governance",
    "statement": "GitHub teams are the primary mechanism for implementing role-based access control at the repository level within an organization. Without any teams, repository access must be granted directly to individual users, making it impossible to enforce consistent access policies, conduct efficient access reviews, or revoke access at scale during offboarding. An organization with no teams has no structured access governance, increasing the risk of privilege creep and unauthorized access.",
    "likelihood_hint": "high",
    "impact_hint": "high",
    "violation_ids": ["no_teams_configured"],
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-269",
        "title": "Improper Privilege Management",
        "url": "https://cwe.mitre.org/data/definitions/269.html"
      },
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-284",
        "title": "Improper Access Control",
        "url": "https://cwe.mitre.org/data/definitions/284.html"
      }
    ],
    "remediation": {
      "title": "Create role-based teams and migrate repository access to team-based grants",
      "description": "Establish GitHub teams that reflect your organizational roles (e.g., developers, maintainers, security, admins). Assign repository access at the team level rather than to individual users to enable consistent access policies, efficient onboarding/offboarding, and auditable access reviews.",
      "tasks": [
        { "title": "Define the access roles required within the organization (e.g., read, write, maintain, admin)" },
        { "title": "Create a GitHub team for each role with a descriptive name and closed visibility" },
        { "title": "Move all direct-user repository access grants to the appropriate team" },
        { "title": "Remove direct user collaborator access from repositories in favour of team-based grants" },
        { "title": "Document team ownership and responsibility in the team description" },
        { "title": "Establish a process for adding/removing users via team membership changes" }
      ]
    }
  }
]

violation[{"id": "no_teams_configured"}] if {
    count(input.teams) == 0
}

title := "Organization has at least one team configured for role-based access control"
description := "The organization must have at least one team defined to support role-based access control. Repository access should be granted via teams rather than directly to individual users."
remarks := "More information: https://docs.github.com/en/organizations/organizing-members-into-teams/about-teams"
