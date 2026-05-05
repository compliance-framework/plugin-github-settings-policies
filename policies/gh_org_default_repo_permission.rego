package compliance_framework.default_repo_permission

risk_templates := [
  {
    "name": "Default repository permission is too permissive",
    "title": "Overly Permissive Default Repository Access Grants Excessive Privileges to All Members",
    "statement": "The default repository permission setting determines the base access level automatically granted to every organization member on all repositories. Setting this to 'write' or 'admin' means that all organization members, including newly onboarded employees and contractors, receive write or administrative access to every repository by default. This violates the principle of least privilege and can lead to unauthorized modifications, accidental data loss, or privilege escalation if any member account is compromised. The default should be 'read' or 'none', with elevated access granted explicitly via team membership.",
    "likelihood_hint": "moderate",
    "impact_hint": "high",
    "violation_ids": ["default_permission_too_permissive"],
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
      },
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-732",
        "title": "Incorrect Permission Assignment for Critical Resource",
        "url": "https://cwe.mitre.org/data/definitions/732.html"
      }
    ],
    "remediation": {
      "title": "Set the default repository permission to 'read' or 'none'",
      "description": "Configure the organization's default repository permission to 'read' or 'none'. Grant write and admin access explicitly via team membership to specific repositories, following the principle of least privilege.",
      "tasks": [
        { "title": "Navigate to Organization Settings > Member privileges > Base permissions" },
        { "title": "Change the base permission to 'Read' or 'No permission'" },
        { "title": "Review all repositories to ensure teams have explicit access grants where write access is required" },
        { "title": "Communicate the change to all members and update onboarding documentation" },
        { "title": "Audit existing repositories for any direct-user write grants that should be team-based" }
      ]
    }
  }
]

_permissive_permissions := {"write", "admin"}

violation[{"id": "default_permission_too_permissive"}] if {
    _permissive_permissions[input.settings.default_repository_permission]
}

title := "Default repository permission is set to 'read' or 'none'"
description := "The organization's default repository permission must not grant write or admin access to all members by default. Elevated access should be granted explicitly via team membership to follow the principle of least privilege."
remarks := "More information: https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/setting-base-permissions-for-an-organization"
