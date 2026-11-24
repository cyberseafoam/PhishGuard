
import re
import ipaddress
from urllib.parse import urlsplit


SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "ow.ly",
    "cutt.ly",
    "rb.gy"
}


def extract_urls(text):
    """Extract unique HTTP and HTTPS URLs from text."""
    urls = re.findall(
        r"https?://[^\s<>\"']+",
        text,
        flags=re.IGNORECASE
    )

    return list(dict.fromkeys(
        url.rstrip(".,);!?]") for url in urls
    ))


def is_ip_address(hostname):
    """Determine whether a hostname is an IP address."""
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def analyze_url(url):
    """Analyze a URL without making network requests."""
    findings = []

    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname or ""
    except ValueError:
        return [{
            "indicator": "Malformed URL",
            "details": url,
            "points": 15
        }]

    if not hostname:
        return [{
            "indicator": "Invalid URL hostname",
            "details": url,
            "points": 15
        }]

    if parsed.scheme.lower() == "http":
        findings.append({
            "indicator": "Insecure HTTP link",
            "details": url,
            "points": 10
        })

    if is_ip_address(hostname):
        findings.append({
            "indicator": "IP address used in URL",
            "details": hostname,
            "points": 20
        })

    if hostname in SHORTENERS:
        findings.append({
            "indicator": "Shortened URL",
            "details": hostname,
            "points": 15
        })

    if parsed.username is not None:
        findings.append({
            "indicator": "Potentially deceptive URL",
            "details": "URL contains user information before the hostname.",
            "points": 20
        })

    if len(url) > 150:
        findings.append({
            "indicator": "Unusually long URL",
            "details": f"URL contains {len(url)} characters.",
            "points": 5
        })

    if hostname.count(".") >= 4:
        findings.append({
            "indicator": "Excessive subdomains",
            "details": hostname,
            "points": 10
        })

    if any(
        part.startswith("xn--")
        for part in hostname.split(".")
    ):
        findings.append({
            "indicator": "Internationalized domain",
            "details": hostname,
            "points": 10
        })

    if hostname.endswith((".xyz", ".top", ".click", ".zip")):
        findings.append({
            "indicator": "Potentially suspicious URL domain",
            "details": hostname,
            "points": 10
        })

    return findings


def check_urls(text):
    """Extract and analyze all URLs in an email."""
    urls = extract_urls(text)
    findings = []

    for url in urls:
        findings.extend(analyze_url(url))

    return urls, findings
