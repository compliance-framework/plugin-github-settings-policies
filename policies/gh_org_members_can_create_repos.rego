package compliance_framework.members_can_create_repos

risk_templates := [
  {
    "name": "Organization members can create repositories without restriction",
    "title": "Unrestricted Repository Creation Undermines Access Governance",
    "statement": "When all organization members are permitted to create repositories, the organization loses control over its asset inventory. Members may inadvertently expose internal code via public repositories, create repositories that bypass security baselines, or accumulate ungoverned codebases. Restricting repository creation to administrators ensures that new repositories are intentional, properly configured, and subject to security review before use.",
    "likelihood_hint": "moderate",
    "impact_hint": "high",
    "violation_ids": ["members_can_create_repos"],
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-284",
        "title": "Improper Access Control",
        "url": "https://cwe.mitre.org/data/definitions/284.html"
      },
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-200",
        "title": "Exposure of Sensitive Information to an Unauthorized Actor",
        "url": "https://cwe.mitre.org/data/definitions/200.html"
      }
    ],
    "remediation": {
      "title": "Restrict repository creation to organization administrators",
      "description": "Disable the ability for regular organization members to create new repositories. Only administrators should be permitted to create repositories, ensuring each new repository is intentionally provisioned and subject to organizational security baselines.",
      "tasks": [
        { "title": "Navigate to Organization Settings > Member privileges" },
        { "title": "Set 'Base permissions' for repository creation to 'None' or restrict to admins only" },
        { "title": "Disable 'Allow members to create repositories' under Repository creation" },
        { "title": "Review and archive any repositories created without administrative approval" },
        { "title": "Document a repository provisioning process that routes requests through an administrator" }
      ]
    }
  }
]

violation[{"id": "members_can_create_repos"}] if {
    input.settings.members_can_create_repositories == true
}

title := "Organization members cannot create repositories"
description := "Repository creation should be restricted to administrators to maintain control over the organization's code asset inventory and prevent ungoverned or accidentally public repositories."
remarks := "More information: https://docs.github.com/en/organizations/managing-organization-settings/restricting-repository-creation-in-your-organization"
