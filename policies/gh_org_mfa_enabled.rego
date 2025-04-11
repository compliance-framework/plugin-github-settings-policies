# METADATA
# title: Github Settings - Organizations - Two Factor Authentication Required
# description: Ensure that 2FA is enabled for all users within the organization, making it harder for TAs to gain access to the organization's repos and settings
# custom:
#   controls:
#     - <control-id>
#   schedule: "* * * * *"


package compliance_framework.mfa_enabled

violation[{}] if {
    input.organization.two_factor_requirement_enabled == false
}

title := "Two Factor Authentication is required at an organization level"
description := "Two factor authentication should be enabled and enforced for all users within the Github Organization to make it harder for malicious actors to gain access to the organizations settings and repositories & settings"
remarks := "More information from Github can be found here: https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-two-factor-authentication-for-your-organization/requiring-two-factor-authentication-in-your-organization"

controls := [
    # SAMA Cyber Security Framework v1.0
    # https://rulebook.sama.gov.sa/en/cyber-security-framework-2
    # Class: SAMA_CSF_1.0
    #
    # 3.3: Cyber Security Operations and Technology
    # https://rulebook.sama.gov.sa/en/33-cyber-security-operations-and-technology-0
    {
        "class": "SAMA_CSF_1.0",
        "control-id": "3.3.5",  # Identity and Access Management https://rulebook.sama.gov.sa/en/335-identity-and-access-management-0
        "statement-ids": [
            "4.e",
            "f.1.a",
        ]
    },

    # NIST SP 800-53 v5.1.1
    # https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
    # Class SP800-53-enhancement
    # ia: Identification and Authentication
    {
        "class": "SP800-53-enhancement",
        "control-id": "ia-2.1",  # Multi-factor Authentication to Privileged Accounts
    },
    {
        "class": "SP800-53-enhancement",
        "control-id": "ia-2.2",  # Multi-factor Authentication for Non-privileged Accounts
    },
]