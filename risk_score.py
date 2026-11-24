
def calculate_score(findings):
    """Calculate a risk score between 0 and 100."""
    unique_indicators = {}

    for finding in findings:
        indicator = finding["indicator"]
        points = finding["points"]

        unique_indicators[indicator] = max(
            unique_indicators.get(indicator, 0),
            points
        )

    return min(sum(unique_indicators.values()), 100)


def get_risk_level(score):
    """Return the risk classification for a score."""
    if score >= 75:
        return "Critical"
    elif score >= 50:
        return "High"
    elif score >= 25:
        return "Moderate"
    else:
        return "Low"


def get_recommendation(level):
    """Return security recommendations based on risk."""
    recommendations = {
        "Critical": (
            "Do not click links, open attachments, or reply. "
            "Report the email to your security team."
        ),
        "High": (
            "Avoid interacting with this email. Verify the "
            "sender through an independent, trusted channel."
        ),
        "Moderate": (
            "Proceed with caution. Verify the sender and "
            "inspect the email before taking action."
        ),
        "Low": (
            "Few suspicious indicators were detected. "
            "However, this does not guarantee the email is safe."
        )
    }

    return recommendations[level]
