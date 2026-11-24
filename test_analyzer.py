
from analyzer import analyze_email
from email_checker import check_keywords, get_sender_domain
from url_checker import extract_urls, analyze_url
from risk_score import calculate_score, get_risk_level


def test_sender_domain():
    assert get_sender_domain(
        "support@example.com"
    ) == "example.com"


def test_sender_display_name():
    assert get_sender_domain(
        "Support <support@example.com>"
    ) == "example.com"


def test_invalid_sender():
    assert get_sender_domain("invalid") == ""


def test_urgent_keywords():
    findings = check_keywords(
        "Urgent",
        "Please respond immediately."
    )

    assert any(
        finding["indicator"] == "Urgent language"
        for finding in findings
    )


def test_sensitive_information():
    findings = check_keywords(
        "",
        "Please verify your password."
    )

    assert any(
        finding["indicator"] == "Sensitive information request"
        for finding in findings
    )


def test_extract_urls():
    text = "Visit https://example.com for more information."

    assert extract_urls(text) == [
        "https://example.com"
    ]


def test_duplicate_urls():
    text = "https://example.com https://example.com"

    assert len(extract_urls(text)) == 1


def test_insecure_url():
    findings = analyze_url("http://example.com")

    assert any(
        finding["indicator"] == "Insecure HTTP link"
        for finding in findings
    )


def test_secure_url():
    assert analyze_url("https://example.com") == []


def test_ip_address_url():
    findings = analyze_url("http://192.0.2.1")

    assert any(
        finding["indicator"] == "IP address used in URL"
        for finding in findings
    )


def test_shortened_url():
    findings = analyze_url("https://bit.ly/example")

    assert any(
        finding["indicator"] == "Shortened URL"
        for finding in findings
    )


def test_deceptive_url():
    findings = analyze_url(
        "https://example.com@another.example"
    )

    assert any(
        finding["indicator"] == "Potentially deceptive URL"
        for finding in findings
    )


def test_risk_score():
    findings = [
        {"indicator": "Urgency", "points": 10},
        {"indicator": "Suspicious URL", "points": 20}
    ]

    assert calculate_score(findings) == 30


def test_duplicate_indicators():
    findings = [
        {"indicator": "Urgency", "points": 10},
        {"indicator": "Urgency", "points": 10}
    ]

    assert calculate_score(findings) == 10


def test_maximum_score():
    findings = [
        {"indicator": "First", "points": 80},
        {"indicator": "Second", "points": 50}
    ]

    assert calculate_score(findings) == 100


def test_risk_levels():
    assert get_risk_level(0) == "Low"
    assert get_risk_level(24) == "Low"
    assert get_risk_level(25) == "Moderate"
    assert get_risk_level(49) == "Moderate"
    assert get_risk_level(50) == "High"
    assert get_risk_level(74) == "High"
    assert get_risk_level(75) == "Critical"
    assert get_risk_level(100) == "Critical"


def test_legitimate_email():
    result = analyze_email(
        "professor@university.example",
        "Class Schedule",
        "Class will begin at 10 AM."
    )

    assert result["risk_level"] == "Low"
    assert result["score"] == 0


def test_phishing_email():
    result = analyze_email(
        "support@paypa1-security.xyz",
        "URGENT: PayPal account suspended",
        (
            "Dear Customer, verify your password "
            "immediately at "
            "http://paypa1-security.xyz/verify"
        )
    )

    assert result["risk_level"] == "Critical"
    assert result["score"] >= 75


def test_brand_domain_spoofing():
    result = analyze_email(
        "support@paypal.com.example",
        "PayPal Account Update",
        "Please review your account."
    )

    assert any(
        finding["indicator"] == "Possible brand impersonation"
        for finding in result["findings"]
    )
