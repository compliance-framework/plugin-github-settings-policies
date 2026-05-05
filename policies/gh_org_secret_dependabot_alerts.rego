package compliance_framework.dependabot_alerts

risk_templates := [
  {
    "name": "Dependabot alerts not enabled by default for new repositories",
    "title": "New Repositories Created Without Vulnerability Alert Coverage",
    "statement": "When no default security configuration has Dependabot alerts enabled for new repositories, any repository created in the organization will silently accumulate vulnerable dependencies without notification. Security teams have no visibility into known CVEs affecting dependencies until alerts are manually enabled, increasing the time-to-detection and the window of exposure.",
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
      "title": "Set a default security configuration with Dependabot alerts enabled for new repositories",
      "description": "Create or update a code security configuration in the organization and mark it as the default for new repositories. Ensure Dependabot alerts is set to 'enabled' in that configuration.",
      "tasks": [
        { "title": "Navigate to Organization Settings > Security > Advanced Security > Configurations" },
        { "title": "Create or edit a security configuration and enable 'Dependabot alerts'" },
        { "title": "Set the configuration as default for new repositories (public, private, or all)" },
        { "title": "Retroactively apply the configuration to existing repositories that lack coverage" },
        { "title": "Establish a process to review and triage new Dependabot alerts within an agreed SLA" }
      ]
    }
  }
]

_default_security_configs := object.get(input, "default_security_configs", [])

_dependabot_alerts_default_enabled if {
    some config in _default_security_configs
    config.configuration.dependabot_alerts == "enabled"
}

_current_config_summary := summary if {
    count(_default_security_configs) == 0
    summary := "No default security configuration is set for the organization."
}

_current_config_summary := summary if {
    count(_default_security_configs) > 0
    entries := [sprintf("'%v' (default_for_new_repos: %v, dependabot_alerts: %v)", [c.configuration.name, c.default_for_new_repos, c.configuration.dependabot_alerts]) | some c in _default_security_configs]
    summary := sprintf("Default security configurations found: [%v]", [concat(", ", entries)])
}

violation[{
    "id": "dependabot_alerts_not_default",
    "description": sprintf(
        "Dependabot alerts are not enabled in any default security configuration. Expected: at least one default configuration with dependabot_alerts = 'enabled'. Current state: %v",
        [_current_config_summary]
    ),
}] if {
    not _dependabot_alerts_default_enabled
}

title := "Dependabot alerts enabled for new repositories"
description := "Checks that at least one default code security configuration exists for the organization with 'dependabot_alerts' set to 'enabled'. This ensures new repositories automatically receive vulnerability alert coverage without manual intervention. Configurations are evaluated via GET /orgs/{org}/code-security/configurations/defaults. A configuration with 'dependabot_alerts: not_set' or 'dependabot_alerts: disabled' does not satisfy this requirement."
remarks := "Checked via GET /orgs/{org}/code-security/configurations/defaults. See https://docs.github.com/en/rest/code-security/configurations#get-default-code-security-configurations"
