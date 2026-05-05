package compliance_framework.sso_enabled

risk_templates := [
  {
    "name": "SAML SSO not enforced for the organization",
    "title": "Absence of SSO Enforcement Bypasses Centralized Identity Governance",
    "statement": "Without SAML Single Sign-On (SSO) enforcement, organization members can authenticate to GitHub using personal credentials that are independent of the organization's identity provider (IdP). This means that off-boarded employees may retain access after their IdP account is disabled, multi-factor authentication enforcement may be inconsistent, and access auditing is fragmented across GitHub and the IdP. Enforcing SAML SSO ensures that every GitHub session is authenticated through the organization's controlled identity provider, enabling centralized access governance, consistent MFA enforcement, and reliable off-boarding.",
    "likelihood_hint": "high",
    "impact_hint": "high",
    "violation_ids": ["sso_not_enabled"],
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-287",
        "title": "Improper Authentication",
        "url": "https://cwe.mitre.org/data/definitions/287.html"
      },
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-306",
        "title": "Missing Authentication for Critical Function",
        "url": "https://cwe.mitre.org/data/definitions/306.html"
      },
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-522",
        "title": "Insufficiently Protected Credentials",
        "url": "https://cwe.mitre.org/data/definitions/522.html"
      }
    ],
    "remediation": {
      "title": "Enable and enforce SAML SSO for the GitHub organization",
      "description": "Configure SAML Single Sign-On for the organization and enforce it so that all members must authenticate via the organization's identity provider. This ensures access is tied to the central IdP lifecycle, enabling reliable off-boarding and consistent MFA.",
      "tasks": [
        { "title": "Navigate to Organization Settings > Authentication security > SAML single sign-on" },
        { "title": "Configure your SAML IdP (e.g., Okta, Azure AD, Google Workspace) with the GitHub SSO endpoint" },
        { "title": "Enable SAML SSO and test authentication with a small group before enforcing" },
        { "title": "Enable 'Require SAML SSO authentication' to enforce for all members" },
        { "title": "Communicate the SSO requirement and migration timeline to all organization members" },
        { "title": "Verify that IdP de-provisioning triggers GitHub access revocation" }
      ]
    }
  }
]

_sso := object.get(input, "sso", {})

_sso_enabled := object.get(_sso, "enabled", false)

_sso_enforced := object.get(_sso, "enforced", false)

_sso_enabled_and_enforced if {
    _sso_enabled
    _sso_enforced
}

violation[{"id": "sso_not_enabled"}] if {
    not _sso_enabled_and_enforced
}

title := "SAML SSO is enabled for the organization"
description := "The GitHub organization must have SAML Single Sign-On enabled and enforced to ensure all member access is authenticated through the organization's centralized identity provider."
remarks := "More information: https://docs.github.com/en/organizations/managing-saml-single-sign-on-for-your-organization/about-identity-and-access-management-with-saml-single-sign-on"
