"""Knowledge base for rule-based agentic cyber security assessment.

The rules intentionally use transparent logic so the student can explain the artefact
in a viva or handover meeting. The lists are not exhaustive; they are designed to
show practical cyber security reasoning aligned with the module learning outcomes.
"""

ASSET_MAP = {
    "Personal data": [
        "Customer or user personal data",
        "Identity records and contact details",
        "Authentication and session data",
    ],
    "Financial data": [
        "Payment records",
        "Banking or transaction data",
        "Fraud monitoring datasets",
    ],
    "AI model or pipeline": [
        "Machine learning model",
        "Training dataset",
        "Prompt templates and system instructions",
        "Model output logs",
    ],
    "Network infrastructure": [
        "Public web services",
        "Internal network segments",
        "Firewall and IDS logs",
    ],
    "Cloud application": [
        "Cloud-hosted application",
        "Object storage buckets",
        "API gateway and secrets",
    ],
    "Operational system": [
        "Business-critical application",
        "Operational database",
        "Service availability and continuity controls",
    ],
}

KEYWORD_THREATS = {
    "phishing": ["Credential theft", "Social engineering", "Account takeover"],
    "ransomware": ["Malware infection", "Data encryption for extortion", "Service disruption"],
    "api": ["API abuse", "Unauthorised data access", "Token leakage"],
    "cloud": ["Cloud misconfiguration", "Public exposure of storage", "Weak IAM controls"],
    "third party": ["Supply-chain compromise", "Vendor data exposure"],
    "ai": ["Prompt injection", "Sensitive data leakage through AI workflow", "Model misuse"],
    "model": ["Model extraction", "Data poisoning", "Adversarial input manipulation"],
    "database": ["SQL injection", "Unauthorised database access", "Data exfiltration"],
    "login": ["Brute-force login", "Credential stuffing", "Session hijacking"],
    "network": ["Lateral movement", "Reconnaissance", "Denial-of-service"],
    "email": ["Business email compromise", "Malicious attachment delivery"],
    "payment": ["Payment fraud", "Transaction manipulation"],
}

DEFAULT_THREATS = [
    "Unauthorised access",
    "Data leakage",
    "Misconfiguration exploitation",
    "Malware or malicious script execution",
    "Denial-of-service or service disruption",
]

VULNERABILITY_RULES = {
    "Weak": [
        "Weak or single-factor authentication",
        "High risk of credential reuse or account takeover",
    ],
    "Moderate": [
        "Authentication controls exist but may require stronger MFA and review",
    ],
    "Strong": [
        "Authentication appears strong but should still be monitored and tested",
    ],
    "Unknown": [
        "Unknown authentication strength creates assurance uncertainty",
    ],
    "Outdated": [
        "Unpatched software or delayed security updates",
        "Known vulnerabilities may remain exploitable",
    ],
    "Partially patched": [
        "Patch coverage is incomplete or inconsistent",
    ],
    "Current": [
        "Patch status is current, but vulnerability scanning should validate this claim",
    ],
    "None": [
        "Limited monitoring and logging",
        "Weak ability to detect attacks or reconstruct incidents",
    ],
    "Basic": [
        "Basic logging may miss suspicious patterns and advanced threats",
    ],
    "Advanced": [
        "Advanced monitoring is present but requires tuning and regular review",
    ],
    "High": [
        "High third-party dependency increases supply-chain and data-sharing risk",
    ],
    "Medium": [
        "Moderate supplier dependency requires contractual and technical assurance",
    ],
    "Low": [
        "Supplier risk appears lower but should remain in periodic review",
    ],
}

CONTROL_LIBRARY = {
    "Confidentiality": [
        "Apply least-privilege access control and role-based permissions",
        "Use multi-factor authentication for privileged and remote access",
        "Encrypt sensitive data at rest and in transit",
        "Review third-party data sharing and minimise unnecessary data collection",
    ],
    "Integrity": [
        "Use secure hashing or digital signatures for critical records",
        "Maintain tamper-evident audit logs",
        "Validate input at API, application and database layers",
        "Use change control and version control for security configuration",
    ],
    "Availability": [
        "Apply backup, recovery and business continuity controls",
        "Use rate limiting and DDoS protection for exposed services",
        "Monitor service health and define incident response escalation",
        "Segment critical services to reduce blast radius",
    ],
}

FIREWALL_BASELINES = [
    "Deny inbound traffic by default and explicitly allow only required business services",
    "Restrict administrative access to VPN, trusted IP ranges or privileged access workstations",
    "Use egress filtering to reduce data exfiltration and command-and-control traffic",
    "Separate public, application and database tiers through network segmentation",
    "Review firewall rules periodically to remove unused, shadowed or overly broad rules",
]

IDS_BASELINES = [
    "Deploy IDS/IPS monitoring at network boundaries and key internal segments",
    "Create alerts for suspicious authentication, scanning, beaconing and unusual outbound traffic",
    "Tune signatures and behavioural rules to reduce false positives",
    "Forward logs to a central SIEM or log platform for correlation and investigation",
    "Test detection coverage using safe simulations or controlled attack emulation",
]

VULN_ASSESSMENT_BASELINES = [
    "Run authenticated vulnerability scans against servers, endpoints and cloud workloads",
    "Prioritise remediation using severity, exploitability and business criticality",
    "Validate patch status after remediation rather than relying only on policy statements",
    "Perform secure configuration review for cloud storage, IAM, network security groups and APIs",
    "Document residual risks and assign accountable owners for unresolved findings",
]

CRYPTOGRAPHY_BASELINES = [
    "Use TLS 1.2+ or TLS 1.3 for data in transit",
    "Use AES-GCM or another authenticated encryption mode for sensitive data at rest",
    "Use SHA-256 or SHA-3 for integrity fingerprinting, not for reversible encryption",
    "Use HMAC or digital signatures where origin integrity and tamper detection are required",
    "Use public-key cryptography for secure key exchange and digital signatures",
    "Store secrets in a managed secret vault and rotate keys periodically",
]

LEGAL_ETHICAL_PRIVACY_BASELINES = [
    "Collect and process only the data needed for the security purpose",
    "Assess whether personal data processing requires a data protection impact assessment",
    "Document lawful basis, retention period and access controls for security logs",
    "Avoid using sensitive data in prompts or AI tools unless authorised and protected",
    "Maintain human review for high-impact security decisions to reduce automation bias",
]

AI_TRANSPARENCY_BASELINES = [
    "The tool uses transparent rule-based logic rather than hidden automated decision-making",
    "Generated recommendations should be reviewed by a human analyst before implementation",
    "The output is decision support and does not replace professional security assessment",
    "The assessment depends on the completeness and accuracy of the scenario input",
]

RATING_DESCRIPTIONS = {
    "Low": "Acceptable with routine monitoring and periodic review.",
    "Medium": "Requires planned remediation and management tracking.",
    "High": "Requires urgent mitigation and clear ownership.",
    "Critical": "Requires immediate escalation and corrective action.",
}
