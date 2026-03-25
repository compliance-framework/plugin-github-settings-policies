package compliance_framework.mfa_enabled

risk_templates := [
  {
    "name": "Organization MFA not enforced",
    "title": "GitHub Organization Members Accessible via Single-Factor Authentication",
    "statement": "Without mandatory two-factor authentication (2FA) enforcement at the organization level, any member account protected only by a password is susceptible to credential-based attacks including phishing, credential stuffing, and brute force. A compromised member account can expose repositories, secrets, CI/CD pipelines, and administrative settings to an attacker without requiring privilege escalation.",
    "likelihood_hint": "high",
    "impact_hint": "high",
    "violation_ids": ["mfa_not_enforced"],
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-308",
        "title": "Use of Single-factor Authentication",
        "url": "https://cwe.mitre.org/data/definitions/308.html"
      },
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-287",
        "title": "Improper Authentication",
        "url": "https://cwe.mitre.org/data/definitions/287.html"
      },
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-522",
        "title": "Insufficiently Protected Credentials",
        "url": "https://cwe.mitre.org/data/definitions/522.html"
      }
    ],
    "remediation": {
      "title": "Enforce two-factor authentication for all organization members",
      "description": "Enable the 'Require two-factor authentication' setting for the GitHub organization so that all current and future members must use 2FA. Members and outside collaborators who do not comply will be removed from the organization until they enable 2FA.",
      "tasks": [
        { "title": "Navigate to Organization Settings > Security > Authentication security" },
        { "title": "Enable 'Require two-factor authentication for everyone in the organization'" },
        { "title": "Audit current member 2FA status before enforcement to avoid accidental removals" },
        { "title": "Communicate the 2FA requirement to all members and collaborators in advance" },
        { "title": "Review and re-invite any removed accounts once they have enabled 2FA" },
        { "title": "Consider enforcing SAML SSO as an additional layer of centralized identity control" }
      ]
    }
  }
]

violation[{"id": "mfa_not_enforced"}] if {
    input.settings.two_factor_requirement_enabled == false
}

title := "Two Factor Authentication is required at an organization level"
description := "Two factor authentication should be enabled and enforced for all users within the Github Organization to make it harder for malicious actors to gain access to the organizations settings and repositories & settings"
remarks := "More information from Github can be found here: https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-two-factor-authentication-for-your-organization/requiring-two-factor-authentication-in-your-organization"
