package compliance_framework.owner_count

risk_templates := [
  {
    "name": "Excessive number of organization owners",
    "title": "Too Many Organization Owners Increases Blast Radius of Privileged Account Compromise",
    "statement": "Organization owners in GitHub hold the highest level of privilege: they can modify security settings, manage all members and teams, access all repositories, and permanently delete the organization. Granting owner access to more than 5 individuals significantly increases the attack surface for privilege abuse, insider threats, and account compromise scenarios. Limiting ownership to a small, well-controlled set ensures that elevated access is deliberately granted and periodically reviewed.",
    "likelihood_hint": "moderate",
    "impact_hint": "high",
    "violation_ids": ["too_many_owners"],
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
      "title": "Reduce organization owner count to 5 or fewer",
      "description": "Review the list of organization owners and remove owner access from any accounts that do not require it. Prefer using team-based admin roles for day-to-day administrative tasks, reserving full organization ownership for a minimal set of accountable individuals.",
      "tasks": [
        { "title": "Navigate to Organization Settings > People > Owners" },
        { "title": "Review the business justification for each owner account" },
        { "title": "Downgrade any owners who do not require full organization-level privileges to member or team maintainer roles" },
        { "title": "Ensure remaining owners have MFA enabled and use strong authentication" },
        { "title": "Schedule a periodic review of organization ownership at least annually" }
      ]
    }
  },
  {
    "name": "Organization owner data is missing",
    "title": "Missing Organization Owner Telemetry Prevents Privileged Access Review",
    "statement": "When the organization owner list is missing from collected GitHub data, the policy cannot verify whether ownership is limited to a small, accountable group. Missing owner telemetry can hide excessive privileged access and prevents reviewers from confirming that organization-level administrative authority is appropriately governed.",
    "likelihood_hint": "moderate",
    "impact_hint": "high",
    "violation_ids": ["owners_missing"],
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
      "title": "Collect organization owner data before evaluating owner-count posture",
      "description": "Update the GitHub organization data collector or input mapping so the policy receives the current list of organization owners. Re-run the policy after owner telemetry is present to verify that the owner count is compliant.",
      "tasks": [
        { "title": "Verify that the GitHub token can read organization owner membership" },
        { "title": "Populate the input owners field with current organization owners" },
        { "title": "Re-run the owner-count policy after collection succeeds" },
        { "title": "Review the collected owner list for stale or unnecessary owner access" }
      ]
    }
  }
]

_owners := object.get(input, "owners", [])

violation[{"id": "owners_missing"}] if {
    not "owners" in object.keys(input)
}

violation[{"id": "too_many_owners"}] if {
    count(_owners) > 5
}

title := "Organization has 5 or fewer owners"
description := "The number of GitHub organization owners should not exceed 5 to limit the blast radius of a privileged account compromise and ensure that elevated access is deliberately granted and regularly reviewed."
remarks := "More information: https://docs.github.com/en/organizations/managing-peoples-access-to-your-organization-with-roles/roles-in-an-organization#organization-owners"
