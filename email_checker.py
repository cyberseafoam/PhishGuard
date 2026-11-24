
import re
from email.utils import parseaddr


URGENT_KEYWORDS = [
    "urgent",
    "immediately",
    "act now",
    "limited time",
    "within 24 hours",
    "final notice",
    "action required",
    "respond now"
]

SENSITIVE_KEYWORDS = [
    "verify your password",
    "confirm your password",
    "enter your password",
    "social security number",
    "credit card number",
    "bank account details",
    "verification code",
    "login credentials",
    "confirm your identity"
]

THREAT_KEYWORDS = [
    "account suspended",
    "account has been suspended",
    "account will be closed",
    "permanent closure",
    "legal action",
    "account terminated",
    "access will be revoked"
]

GENERIC_GREETINGS = [
    "dear customer",
    "dear user",
    "dear account holder",
    "dear valued customer",
    "dear sir or madam"
]

BRANDS = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "outlook.com", "live.com"],
    "google": ["google.com", "gmail.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com"],
    "netflix": ["netflix.com"]
}


def check_keywords(subject, body):
    """Detect suspicious language in an email."""
    text = f"{subject} {body}".lower()
    findings = []

    categories = [
        ("Urgent language", URGENT_KEYWORDS, 10),
        ("Sensitive information request", SENSITIVE_KEYWORDS, 20),
        ("Threatening language", THREAT_KEYWORDS, 10),
        ("Generic greeting", GENERIC_GREETINGS, 5)
    ]

    for category, keywords, points in categories:
        matches = [
            word for word in keywords
            if re.search(r"\b" + re.escape(word) + r"\b", text)
        ]

        if matches:
            findings.append({
                "indicator": category,
                "details": ", ".join(matches),
                "points": points
            })

    return findings


def get_sender_domain(sender):
    """Extract the domain from a sender email address."""
    _, address = parseaddr(sender)

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", address):
        return ""

    return address.rsplit("@", 1)[1].lower().rstrip(".")


def domain_matches(domain, official_domain):
    """Check whether a domain belongs to an official domain."""
    return (
        domain == official_domain
        or domain.endswith("." + official_domain)
    )


def check_sender(sender, subject, body):
    """Analyze sender addresses for suspicious indicators."""
    findings = []
    domain = get_sender_domain(sender)

    if not domain:
        findings.append({
            "indicator": "Invalid or missing sender",
            "details": "The sender address could not be validated.",
            "points": 10
        })
        return findings

    suspicious_tlds = (
        ".xyz", ".top", ".click", ".work", ".zip"
    )

    if domain.endswith(suspicious_tlds):
        findings.append({
            "indicator": "Potentially suspicious sender domain",
            "details": domain,
            "points": 10
        })

    display_name, _ = parseaddr(sender)
    claimed_identity = f"{display_name} {subject}".lower()

    for brand, official_domains in BRANDS.items():
        if re.search(r"\b" + re.escape(brand) + r"\b", claimed_identity):
            official = any(
                domain_matches(domain, official_domain)
                for official_domain in official_domains
            )

            if not official:
                findings.append({
                    "indicator": "Possible brand impersonation",
                    "details": (
                        f"Email references {brand.title()}, "
                        f"but the sender domain is {domain}."
                    ),
                    "points": 25
                })
                break

    if domain.count("-") >= 3:
        findings.append({
            "indicator": "Unusual sender domain",
            "details": "Sender domain contains multiple hyphens.",
            "points": 5
        })

    return findings
