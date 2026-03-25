package compliance_framework.secret_scanning

risk_templates := [
  {
    "name": "Secret scanning not enabled by default for new repositories",
    "title": "New Repositories Created Without Secret Detection Coverage",
    "statement": "When secret scanning is not enabled by default at the organization level, any new repository created will lack automatic detection of committed credentials. API keys, tokens, certificates, and passwords pushed to these repositories will go undetected until scanning is manually enabled, leaving an indefinite window during which exposed secrets can be harvested and abused.",
    "likelihood_hint": "high",
    "impact_hint": "high",
    "violation_ids": ["secret_scanning_not_default"],
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-312",
        "title": "Cleartext Storage of Sensitive Information",
        "url": "https://cwe.mitre.org/data/definitions/312.html"
      },
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-522",
        "title": "Insufficiently Protected Credentials",
        "url": "https://cwe.mitre.org/data/definitions/522.html"
      },
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-798",
        "title": "Use of Hard-coded Credentials",
        "url": "https://cwe.mitre.org/data/definitions/798.html"
      }
    ],
    "remediation": {
      "title": "Enable secret scanning by default for all new repositories",
      "description": "Configure the GitHub organization to automatically enable secret scanning on every new repository. Extend coverage retroactively to existing repositories that currently lack it.",
      "tasks": [
        { "title": "Navigate to Organization Settings > Code security and analysis" },
        { "title": "Enable 'Secret scanning' for all new repositories" },
        { "title": "Retroactively enable secret scanning on all existing repositories" },
        { "title": "Review all existing secret scanning alerts and revoke any exposed credentials immediately" },
        { "title": "Configure push protection at the organization level to block secrets before they enter the repository" },
        { "title": "Establish a runbook for responding to secret scanning alerts within an agreed SLA" }
      ]
    }
  }
]

violation[{"id": "secret_scanning_not_default"}] if {
    input.secret_scanning_enabled_for_new_repositories == false
}

title := "Secret Scanning is enabled for new repositories in the organization"
description := "All new repositories should be set up for secret scanning as the default."
remarks := "Endpoint is closing down at some point and moving to code security configurations: See https://docs.github.com/rest/code-security/configurations"
