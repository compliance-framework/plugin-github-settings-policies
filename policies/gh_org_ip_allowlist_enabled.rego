package compliance_framework.ip_allowlist_enabled

risk_templates := [
  {
    "name": "No IP allow-list configured for the organization",
    "title": "Absence of IP Allow-List Exposes GitHub Resources to Access from Untrusted Networks",
    "statement": "Without an IP allow-list, the GitHub organization's resources (repositories, API, settings) are accessible from any IP address on the internet, subject only to authentication. This means that even valid credentials used from untrusted networks (e.g., compromised endpoints, attacker infrastructure) can interact with the organization's assets. Configuring an IP allow-list restricts access to approved network ranges, adding a network-layer control that limits the blast radius of credential compromise.",
    "likelihood_hint": "moderate",
    "impact_hint": "high",
    "violation_ids": ["ip_allowlist_not_configured"],
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-284",
        "title": "Improper Access Control",
        "url": "https://cwe.mitre.org/data/definitions/284.html"
      },
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-923",
        "title": "Improper Restriction of Communication Channel to Intended Endpoints",
        "url": "https://cwe.mitre.org/data/definitions/923.html"
      }
    ],
    "remediation": {
      "title": "Configure an IP allow-list for the GitHub organization",
      "description": "Enable the IP allow-list feature for the organization and add the approved IP ranges from which members are permitted to access GitHub. This restricts access to known, trusted networks and reduces the risk of credential-based attacks from untrusted locations.",
      "tasks": [
        { "title": "Navigate to Organization Settings > Security > IP allow list" },
        { "title": "Enable 'IP allow list'" },
        { "title": "Add approved IP ranges for corporate offices, VPNs, and CI/CD infrastructure" },
        { "title": "Test that members can still access GitHub from approved networks before fully enforcing" },
        { "title": "Document the process for requesting additions to the IP allow-list" },
        { "title": "Schedule periodic review of the IP allow-list to remove stale entries" }
      ]
    }
  }
]

_ip_allow_list := object.get(input, "ip_allow_list", [])

_has_active_entry if {
    some entry in _ip_allow_list
    entry.is_active == true
}

violation[{"id": "ip_allowlist_not_configured"}] if {
    not _has_active_entry
}

title := "Organization has an active IP allow-list configured"
description := "The GitHub organization must have at least one active IP allow-list entry to restrict access to approved network ranges and reduce the risk of access from untrusted locations."
remarks := "More information: https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/managing-allowed-ip-addresses-for-your-organization"
