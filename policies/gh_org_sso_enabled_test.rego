package compliance_framework.sso_enabled

test_sso_enabled if {
    count(violation) == 0 with input as {
        "sso": {
            "enabled": true,
            "sso_url": "https://sso.example.com/saml/github",
            "idp_issuer": "https://sso.example.com"
        }
    }
}

test_sso_disabled if {
    count(violation) > 0 with input as {
        "sso": {
            "enabled": false,
            "sso_url": "",
            "idp_issuer": ""
        }
    }
}
