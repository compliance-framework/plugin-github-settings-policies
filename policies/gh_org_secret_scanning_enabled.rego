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
      "title": "Set a default security configuration with secret scanning enabled for new repositories",
      "description": "Create or update a code security configuration in the organization and mark it as the default for new repositories. Ensure secret scanning is set to 'enabled' in that configuration.",
      "tasks": [
        { "title": "Navigate to Organization Settings > Security > Advanced Security > Configurations" },
        { "title": "Create or edit a security configuration and enable 'Secret scanning'" },
        { "title": "Set the configuration as default for new repositories (public, private, or all)" },
        { "title": "Retroactively apply the configuration to existing repositories that lack coverage" },
        { "title": "Review all existing secret scanning alerts and revoke any exposed credentials immediately" },
        { "title": "Establish a runbook for responding to secret scanning alerts within an agreed SLA" }
      ]
    }
  }
]

_default_security_configs := object.get(input, "default_security_configs", [])

_secret_scanning_enabled_for_all_new_repos if {
    some config in _default_security_configs
    config.default_for_new_repos == "all"
    config.configuration.secret_scanning == "enabled"
}

_secret_scanning_enabled_for_all_new_repos if {
    some public_config in _default_security_configs
    public_config.default_for_new_repos == "public"
    public_config.configuration.secret_scanning == "enabled"

    some private_config in _default_security_configs
    private_config.default_for_new_repos == "private_and_internal"
    private_config.configuration.secret_scanning == "enabled"
}

_secret_scanning_config_summary := summary if {
    count(_default_security_configs) == 0
    summary := "No default security configuration is set for the organization."
}

_secret_scanning_config_summary := summary if {
    count(_default_security_configs) > 0
    entries := [sprintf("'%v' (default_for_new_repos: %v, secret_scanning: %v)", [c.configuration.name, c.default_for_new_repos, c.configuration.secret_scanning]) | some c in _default_security_configs]
    summary := sprintf("Default security configurations found: [%v]", [concat(", ", entries)])
}

violation[{
    "id": "secret_scanning_not_default",
    "description": sprintf(
        "Secret scanning is not enabled for all new repositories. Expected: an 'all' default configuration with secret_scanning = 'enabled', or enabled defaults for both public and private/internal repositories. Current state: %v",
        [_secret_scanning_config_summary]
    )
}] if {
    not _secret_scanning_enabled_for_all_new_repos
}

title := "Secret Scanning is enabled for new repositories in the organization"
description := "Checks that default code security configurations enable secret scanning for all new repositories in the organization. This requires an 'all' default configuration with 'secret_scanning' set to 'enabled', or enabled defaults for both public and private/internal repositories. Configurations are evaluated via GET /orgs/{org}/code-security/configurations/defaults. A configuration with 'secret_scanning: not_set' or 'secret_scanning: disabled' does not satisfy this requirement."
remarks := "Checked via GET /orgs/{org}/code-security/configurations/defaults. See https://docs.github.com/en/rest/code-security/configurations#get-default-code-security-configurations"
