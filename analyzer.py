
from email_checker import check_keywords, check_sender
from url_checker import check_urls
from risk_score import (
    calculate_score,
    get_risk_level,
    get_recommendation
)


def analyze_email(sender, subject, body):
    """Perform a complete phishing analysis."""
    findings = []

    findings.extend(check_keywords(subject, body))
    findings.extend(check_sender(sender, subject, body))

    urls, url_findings = check_urls(f"{subject}\n{body}")
    findings.extend(url_findings)

    findings.sort(
        key=lambda finding: finding["points"],
        reverse=True
    )

    score = calculate_score(findings)
    level = get_risk_level(score)

    return {
        "sender": sender,
        "subject": subject,
        "score": score,
        "risk_level": level,
        "findings": findings,
        "urls": urls,
        "recommendation": get_recommendation(level)
    }
