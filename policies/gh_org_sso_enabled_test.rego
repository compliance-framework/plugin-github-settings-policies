package compliance_framework.sso_enabled

test_sso_enabled if {
    count(violation) == 0 with input as {
        "sso": {
            "enabled": true,
            "enforced": true,
            "sso_url": "https://sso.example.com/saml/github",
            "idp_issuer": "https://sso.example.com"
        }
    }
}

test_sso_disabled if {
    count(violation) == 1 with input as {
        "sso": {
            "enabled": false,
            "enforced": false,
            "sso_url": "",
            "idp_issuer": ""
        }
    }
}

test_sso_enabled_but_not_enforced if {
    count(violation) == 1 with input as {
        "sso": {
            "enabled": true,
            "enforced": false,
            "sso_url": "https://sso.example.com/saml/github",
            "idp_issuer": "https://sso.example.com"
        }
    }
}

test_sso_missing if {
    count(violation) == 1 with input as {}
}
