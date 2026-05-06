package compliance_framework.web_commit_signoff

risk_templates := [
  {
    "name": "Web commit sign-off not required",
    "title": "Unsigned Web Commits Undermine Change Attribution and Audit Trail Integrity",
    "statement": "When web commit sign-off is not enforced, commits made via the GitHub web interface lack a Developer Certificate of Origin (DCO) sign-off, which reduces the integrity of the change attribution record. In compliance contexts, every code change should be traceable to an accountable individual. Without sign-off enforcement, commits made through the web UI can bypass the DCO attestation expected for change management controls, creating gaps in the audit trail.",
    "likelihood_hint": "moderate",
    "impact_hint": "moderate",
    "violation_ids": ["web_commit_signoff_not_required"],
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-778",
        "title": "Insufficient Logging",
        "url": "https://cwe.mitre.org/data/definitions/778.html"
      },
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-345",
        "title": "Insufficient Verification of Data Authenticity",
        "url": "https://cwe.mitre.org/data/definitions/345.html"
      }
    ],
    "remediation": {
      "title": "Enable web commit sign-off for the organization",
      "description": "Configure the GitHub organization to require a sign-off on all commits made via the web interface. This ensures that every commit carries a Developer Certificate of Origin, maintaining a complete and attributable audit trail for change management compliance.",
      "tasks": [
        { "title": "Navigate to Organization Settings > Repository defaults" },
        { "title": "Enable 'Require contributors to sign off on web-based commits'" },
        { "title": "Communicate the sign-off requirement to all contributors who use the GitHub web editor" },
        { "title": "Consider also enforcing GPG or SSH commit signing for locally-pushed commits via branch protection rules" }
      ]
    }
  }
]

_settings := object.get(input, "settings", {})

_web_commit_signoff_required := object.get(_settings, "web_commit_signoff_required", false)

violation[{"id": "web_commit_signoff_not_required"}] if {
    not _web_commit_signoff_required
}

title := "Web commit sign-off is required for the organization"
description := "All commits made via the GitHub web interface must carry a sign-off to ensure attribution integrity and support change management audit trail requirements."
remarks := "More information: https://docs.github.com/en/organizations/managing-organization-settings/managing-the-commit-signoff-policy-for-your-organization"
