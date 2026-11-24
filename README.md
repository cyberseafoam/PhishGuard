# 🛡️ PhishGuard

**Phishing email detection and security analysis in Python and Streamlit.**

PhishGuard is a rule-based, educational security tool that examines an email's sender, subject, body, and embedded URLs. It highlights suspicious indicators, assigns a **heuristic risk score from 0–100**, and offers actionable recommendations.

> **Important:** A low score does **not** guarantee an email is safe. This tool is not an email authentication service, threat-intelligence lookup, or replacement for enterprise email protection.

## Features

- **Email analysis:** Detect urgency, threats, requests for sensitive information, and generic greetings.
- **Sender checks:** Extract the sender domain and flag potentially unusual domains or possible brand impersonation.
- **URL analysis:** Identify HTTP links, IP-address hosts, URL shorteners, deceptive user-info URLs, unusually long URLs, and other URL patterns.
- **Risk score:** Combine distinct indicator categories into a capped 0–100 score.
- **Interactive dashboard:** Inspect findings and visualize risk with a Plotly gauge.
- **Sample emails:** Load fictional examples to try the analyzer.
- **Export:** Download analysis results as JSON.
- **Automated tests:** Run tests using pytest.

## Quick start

Requires **Python 3.10+**.

```bash
git clone https://github.com/cyberseafoam/PhishGuard.git
cd PhishGuard
python -m venv .venv
```

Activate the virtual environment:

- **Windows (PowerShell):** ` .\.venv\Scripts\Activate.ps1 `
- **macOS / Linux:** `source .venv/bin/activate`

Install dependencies and start the app:

```bash
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

Streamlit normally opens the local app at `http://localhost:8501`.

## Running tests

```bash
python -m pytest -v
```

GitHub Actions runs the test suite automatically on pushes and pull requests to `main`.

## How scoring works

Rules produce findings with associated point values. A finding category contributes at most once, even when repeated. The total is capped at 100.

| Score | Classification |
| --- | --- |
| 0–24 | Low |
| 25–49 | Moderate |
| 50–74 | High |
| 75–100 | Critical |

**These thresholds and weights are illustrative and have not been validated on a representative dataset.** They are *not* probabilities that an email is phishing. Legitimate messages can trigger rules, and sophisticated phishing emails can evade them.

## Privacy and safety

- **Local use:** The analyzer parses text and URLs locally and does **not** fetch or open detected links.
- **Hosted use:** When deployed to a service such as Streamlit Community Cloud, email content is processed on that hosting provider's infrastructure. **Do not paste confidential or sensitive emails into a public deployment.**
- The app does not inspect attachments or verify sender ownership, SPF, DKIM, or DMARC.
- For suspicious messages, navigate to the organization's official site independently instead of following links in the message.
- Use sample/fictional email data when demonstrating the tool publicly.

## Project structure

```text
PhishGuard/
├── app.py               # Streamlit dashboard
├── analyzer.py          # Coordinates all detection checks
├── email_checker.py     # Keyword and sender checks
├── url_checker.py       # URL extraction and heuristic checks
├── risk_score.py        # Scoring and recommendations
├── test_analyzer.py     # Automated tests
├── requirements.txt
├── .gitignore
└── .github/workflows/tests.yml
```

## Tech stack

Python · Streamlit · Pandas · Plotly · pytest · regular expressions · standard library URL parsing

## Roadmap

- [ ] Analyze imported `.eml` email messages and relevant headers.
- [ ] Evaluate authentication results (SPF, DKIM, DMARC) from trustworthy header context.
- [ ] Improve domain/brand matching and minimize false positives.
- [ ] Compare rule performance against labeled phishing and legitimate messages.
- [ ] Add optional, privacy-aware threat intelligence lookups.
- [ ] Add a polished demo screenshot and public deployment link.

## Author

**Connor Dindinger** · Cybersecurity student at Brigham Young University

Built as a personal cybersecurity portfolio project for defensive research and learning.
