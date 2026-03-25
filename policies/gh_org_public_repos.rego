package compliance_framework.public_repos

risk_templates := [
  {
    "name": "Organization has public repositories",
    "title": "Public Repositories Expose Source Code and Organizational Assets",
    "statement": "Public repositories in a GitHub organization are accessible to anyone on the internet without authentication. For organizations that intend to operate privately, unintentional public repos can expose proprietary source code, configuration files, internal tooling, infrastructure details, or secrets committed to version history. This information can be used by attackers to map attack surfaces, extract credentials, or exploit vulnerabilities in the exposed codebase.",
    "likelihood_hint": "high",
    "impact_hint": "high",
    "violation_ids": ["public_repos_present"],
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-200",
        "title": "Exposure of Sensitive Information to an Unauthorized Actor",
        "url": "https://cwe.mitre.org/data/definitions/200.html"
      },
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-284",
        "title": "Improper Access Control",
        "url": "https://cwe.mitre.org/data/definitions/284.html"
      }
    ],
    "remediation": {
      "title": "Convert public repositories to private or archive them",
      "description": "Review all public repositories in the organization and convert any that should not be publicly accessible to private visibility. Archive any obsolete repositories to prevent accidental disclosure.",
      "tasks": [
        { "title": "Audit all public repositories in the organization" },
        { "title": "Review repository contents and git history for exposed credentials, configuration, or internal documentation" },
        { "title": "Rotate any credentials or secrets found in public repository history before changing visibility" },
        { "title": "Convert non-intentionally public repositories to private" },
        { "title": "Archive or delete obsolete public repositories" },
        { "title": "Enable secret scanning on all repositories to detect any remaining exposed credentials" }
      ]
    }
  },
  {
    "name": "Organization has public gists",
    "title": "Public Gists May Expose Sensitive Scripts or Configuration",
    "statement": "Public gists associated with an organization's members can inadvertently expose internal scripts, configuration snippets, credentials, or operational procedures. Because gists are often used informally, developers may not realize that content shared via a public gist is indexed and discoverable by anyone.",
    "likelihood_hint": "moderate",
    "impact_hint": "moderate",
    "violation_ids": ["public_gists_present"],
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-200",
        "title": "Exposure of Sensitive Information to an Unauthorized Actor",
        "url": "https://cwe.mitre.org/data/definitions/200.html"
      },
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-538",
        "title": "Insertion of Sensitive Information into Externally-Accessible File or Directory",
        "url": "https://cwe.mitre.org/data/definitions/538.html"
      }
    ],
    "remediation": {
      "title": "Remove or make private all public gists",
      "description": "Review all public gists associated with organization members and convert any containing sensitive or internal content to secret gists, or delete them entirely.",
      "tasks": [
        { "title": "Audit all public gists owned by organization members" },
        { "title": "Convert gists containing sensitive content to secret gists or delete them" },
        { "title": "Educate members on the risks of sharing internal content via public gists" },
        { "title": "Establish a policy prohibiting the use of public gists for internal scripts or configuration" }
      ]
    }
  }
]

violation[{"id": "public_repos_present"}] if {
	input.settings.public_repos > 0
}

violation[{"id": "public_gists_present"}] if {
	input.settings.public_gists > 0
}

title := "No Public Repos or Gists"
description := "The Organization should not have any public repositories or gists attached to it"
