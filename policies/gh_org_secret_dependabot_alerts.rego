package compliance_framework.dependabot_alerts

risk_templates := [
  {
    "name": "Dependabot alerts not enabled by default for new repositories",
    "title": "New Repositories Created Without Vulnerability Alert Coverage",
    "statement": "When Dependabot alerts are not enabled by default for new repositories, any repository created in the organization will silently accumulate vulnerable dependencies without notification. Security teams have no visibility into known CVEs affecting dependencies in these repositories until alerts are manually enabled, increasing the time-to-detection and the window of exposure.",
    "likelihood_hint": "moderate",
    "impact_hint": "high",
    "violation_ids": ["dependabot_alerts_not_default"],
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-693",
        "title": "Protection Mechanism Failure",
        "url": "https://cwe.mitre.org/data/definitions/693.html"
      },
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-1395",
        "title": "Dependency on Vulnerable Third-Party Component",
        "url": "https://cwe.mitre.org/data/definitions/1395.html"
      }
    ],
    "remediation": {
      "title": "Enable Dependabot alerts by default for all new repositories",
      "description": "Configure the GitHub organization so that Dependabot alerts are automatically enabled for every new repository created. This ensures that vulnerability detection is active from the moment a repository is initialized.",
      "tasks": [
        { "title": "Navigate to Organization Settings > Code security and analysis" },
        { "title": "Enable 'Dependabot alerts' for all new repositories" },
        { "title": "Retroactively enable Dependabot alerts on existing repositories that currently lack coverage" },
        { "title": "Establish a process to review and triage new Dependabot alerts within an agreed SLA" },
        { "title": "Consider also enabling Dependabot security updates to automate remediation PRs" }
      ]
    }
  }
]

violation[{"id": "dependabot_alerts_not_default"}] if {
    input.dependabot_alerts_enabled_for_new_repositories == false
}

title := "Dependabot alerts enabled for new repositories"
description := "All new repositories should be set up to alert for any dependabot alerts that are coming from the repositories"
remarks := "Endpoint is closing down at some point and moving to code security configurations: See https://docs.github.com/rest/code-security/configurations"
