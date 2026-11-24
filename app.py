
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import json

from analyzer import analyze_email


st.set_page_config(
    page_title="PhishGuard",
    page_icon="🛡️",
    layout="wide"
)


# ------------------------------
# CUSTOM STYLING
# ------------------------------

st.markdown("""
<style>
    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
        max-width: 1200px;
    }

    div[data-testid="stMetric"] {
        border: 1px solid #334155;
        padding: 20px;
        border-radius: 12px;
    }

    .stButton > button {
        width: 100%;
        border-radius: 8px;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)


# ------------------------------
# SAMPLE EMAILS
# ------------------------------

SAMPLE_EMAILS = {
    "Suspicious Email": {
        "sender": "PayPal Support <support@paypa1-security.xyz>",
        "subject": "URGENT: PayPal account suspended",
        "body": (
            "Dear Customer,\n\n"
            "Your account has been suspended due to "
            "suspicious activity.\n\n"
            "You must verify your password immediately "
            "to prevent permanent closure.\n\n"
            "Visit the following link:\n"
            "http://paypa1-security.xyz/verify\n\n"
            "Thank you,\n"
            "PayPal Security Team"
        )
    },

    "Legitimate Email": {
        "sender": "professor@university.example",
        "subject": "Class Schedule Update",
        "body": (
            "Hello,\n\n"
            "Our class will meet at the regular time "
            "on Monday. Please bring your textbook "
            "and completed assignment.\n\n"
            "Thank you!"
        )
    },

    "Moderate Risk Email": {
        "sender": "notifications@company.example",
        "subject": "Action required: Update your profile",
        "body": (
            "Dear User,\n\n"
            "Please update your profile within 24 hours.\n\n"
            "Visit http://company.example/profile "
            "to review your account settings.\n\n"
            "Thank you."
        )
    }
}


# ------------------------------
# SESSION STATE
# ------------------------------

for key in ["sender", "subject", "body"]:
    if key not in st.session_state:
        st.session_state[key] = ""

if "result" not in st.session_state:
    st.session_state.result = None


def load_sample(name):
    """Load a sample email into the input fields."""
    sample = SAMPLE_EMAILS[name]

    st.session_state.sender = sample["sender"]
    st.session_state.subject = sample["subject"]
    st.session_state.body = sample["body"]
    st.session_state.result = None


def clear_email():
    """Clear the current email and analysis."""
    st.session_state.sender = ""
    st.session_state.subject = ""
    st.session_state.body = ""
    st.session_state.result = None


# ------------------------------
# RISK GAUGE
# ------------------------------

def create_gauge(score):
    """Create an interactive phishing risk gauge."""
    if score >= 75:
        color = "#dc2626"
    elif score >= 50:
        color = "#f97316"
    elif score >= 25:
        color = "#eab308"
    else:
        color = "#22c55e"

    figure = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        number={"suffix": " / 100"},
        title={"text": "Phishing Risk Score"},
        gauge={
            "axis": {"range": [0, 100]},
            "bar": {"color": color},
            "steps": [
                {"range": [0, 25], "color": "#dcfce7"},
                {"range": [25, 50], "color": "#fef9c3"},
                {"range": [50, 75], "color": "#ffedd5"},
                {"range": [75, 100], "color": "#fee2e2"}
            ]
        }
    ))

    figure.update_layout(
        height=300,
        margin=dict(l=30, r=30, t=60, b=20),
        paper_bgcolor="rgba(0,0,0,0)"
    )

    return figure


# ------------------------------
# SIDEBAR
# ------------------------------

with st.sidebar:
    st.title("🛡️ PhishGuard")

    st.caption("Email Security Analysis Tool")

    st.divider()

    st.subheader("Navigation")

    page = st.radio(
        "Select a page",
        ["Email Analyzer", "How It Works", "About"],
        label_visibility="collapsed"
    )

    st.divider()

    st.subheader("Sample Emails")

    for sample_name in SAMPLE_EMAILS:
        st.button(
            sample_name,
            on_click=load_sample,
            args=(sample_name,)
        )

    st.button("Clear Email", on_click=clear_email)

    st.divider()

    st.caption("Version 1.0.0")
    st.caption("Built with Python and Streamlit")


# ------------------------------
# EMAIL ANALYZER PAGE
# ------------------------------

if page == "Email Analyzer":

    st.title("🛡️ PhishGuard")
    st.write("Phishing Email Detection & Security Analysis")

    st.info(
        "Analyze suspicious emails without opening their links. "
        "This tool uses rule-based security indicators."
    )

    st.subheader("Email Information")

    sender = st.text_input(
        "Sender Email Address",
        key="sender",
        placeholder="sender@example.com"
    )

    subject = st.text_input(
        "Email Subject",
        key="subject",
        placeholder="Enter the email subject"
    )

    body = st.text_area(
        "Email Content",
        key="body",
        height=250,
        placeholder="Paste the email content here..."
    )

    if st.button("🔍 Analyze Email", type="primary"):

        if not body.strip():
            st.session_state.result = None
            st.warning("Please enter the email content.")

        else:
            with st.spinner("Analyzing email..."):
                st.session_state.result = analyze_email(
                    sender,
                    subject,
                    body
                )
                st.session_state.analyzed_body = body

    result = st.session_state.result

    if result is not None:

        if (
            result["sender"] != sender
            or result["subject"] != subject
            or st.session_state.get("analyzed_body", body) != body
        ):
            st.caption(
                "Inputs may have changed. Analyze again "
                "to refresh the results."
            )

        st.divider()
        st.header("Analysis Results")

        score = result["score"]
        level = result["risk_level"]
        findings = result["findings"]
        urls = result["urls"]

        col1, col2, col3, col4 = st.columns(4)

        col1.metric("Risk Score", f"{score}/100")
        col2.metric("Risk Level", level)
        col3.metric("Indicators Found", len(findings))
        col4.metric("URLs Detected", len(urls))

        left, right = st.columns(2)

        with left:
            st.plotly_chart(
                create_gauge(score),
                use_container_width=True
            )

        with right:
            st.subheader("Security Assessment")

            if level == "Critical":
                st.error("Critical phishing risk detected.")
            elif level == "High":
                st.error("High phishing risk detected.")
            elif level == "Moderate":
                st.warning("Moderate phishing risk detected.")
            else:
                st.success("Low phishing risk detected.")

            st.write(result["recommendation"])

        st.divider()

        # Detected indicators

        st.subheader("🚩 Detected Security Indicators")

        if findings:
            dataframe = pd.DataFrame(findings)

            dataframe = dataframe.rename(columns={
                "indicator": "Indicator",
                "details": "Details",
                "points": "Risk Points"
            })

            st.dataframe(
                dataframe,
                use_container_width=True,
                hide_index=True
            )

            st.caption(
                "Repeated indicator categories are counted "
                "only once in the overall risk score."
            )

            for finding in findings:
                with st.expander(
                    f'{finding["indicator"]} '
                    f'(+{finding["points"]} points)'
                ):
                    st.text(finding["details"])

        else:
            st.success(
                "No known suspicious indicators were detected."
            )

        st.divider()

        # URL analysis

        st.subheader("🔗 Extracted URLs")

        if urls:
            for index, url in enumerate(urls, start=1):
                st.write(f"URL {index}")
                st.code(url, language=None)

            st.warning(
                "These URLs have not been visited or verified. "
                "Do not open suspicious links."
            )

        else:
            st.info("No HTTP or HTTPS URLs were detected.")

        st.divider()

        # Downloadable report

        st.subheader("📄 Security Report")

        report = json.dumps(result, indent=4)

        st.download_button(
            label="Download Analysis Report",
            data=report,
            file_name="phishguard_report.json",
            mime="application/json"
        )

        st.caption(
            "The risk score is a heuristic rating, "
            "not a statistical probability of phishing."
        )


# ------------------------------
# HOW IT WORKS PAGE
# ------------------------------

elif page == "How It Works":

    st.title("How PhishGuard Works")

    st.write(
        "PhishGuard uses rule-based detection to identify "
        "common phishing indicators in email messages."
    )

    st.subheader("Detection Process")

    st.markdown("""
    1. The user enters the sender, subject, and email body.
    2. The application searches for suspicious language.
    3. The sender domain is analyzed.
    4. URLs are extracted and inspected.
    5. Detected indicators receive risk points.
    6. The overall score determines the risk classification.
    """)

    st.subheader("Risk Scoring")

    scoring_data = {
        "Indicator": [
            "Urgent language",
            "Sensitive information request",
            "Threatening language",
            "Generic greeting",
            "Possible brand impersonation",
            "Suspicious sender domain",
            "Insecure HTTP link",
            "IP address in URL",
            "Shortened URL",
            "Deceptive URL",
            "Unusually long URL"
        ],
        "Points": [
            10, 20, 10, 5, 25, 10,
            10, 20, 15, 20, 5
        ]
    }

    st.dataframe(
        pd.DataFrame(scoring_data),
        hide_index=True,
        use_container_width=True
    )

    st.subheader("Risk Classifications")

    st.success("0–24: Low Risk")
    st.warning("25–49: Moderate Risk")
    st.error("50–74: High Risk")
    st.error("75–100: Critical Risk")

    st.subheader("Limitations")

    st.markdown("""
    - PhishGuard cannot guarantee that an email is safe.
    - Legitimate emails may contain suspicious indicators.
    - Some phishing emails may evade rule-based detection.
    - URLs are not visited or checked against live databases.
    - Sender authentication is not verified.
    - Attachments are not analyzed.
    - Risk scores are not calibrated probabilities.
    """)


# ------------------------------
# ABOUT PAGE
# ------------------------------

elif page == "About":

    st.title("About PhishGuard")

    st.write(
        "PhishGuard is a personal cybersecurity project "
        "designed to demonstrate phishing detection, "
        "security analysis, and software development."
    )

    st.subheader("Developer")

    st.write("Connor Dindinger")
    st.write("Cybersecurity Student | Brigham Young University")

    st.subheader("Technologies Used")

    st.markdown("""
    - Python
    - Streamlit
    - Pandas
    - Plotly
    - Regular Expressions
    - Pytest
    """)

    st.subheader("Cybersecurity Concepts")

    st.markdown("""
    - Social engineering
    - Phishing detection
    - Email security
    - URL analysis
    - Domain impersonation
    - Threat identification
    - Risk assessment
    - Security reporting
    """)

    st.subheader("Future Improvements")

    st.markdown("""
    - Email header analysis
    - EML file uploads
    - SPF, DKIM, and DMARC analysis
    - Threat intelligence integration
    - Machine learning classification
    - PDF security reports
    """)

    st.divider()

    st.caption(
        "This application is intended for educational "
        "and defensive cybersecurity purposes."
    )
