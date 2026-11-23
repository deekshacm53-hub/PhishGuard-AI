import streamlit as st
import re
import os
import csv
import socket
import requests
import ipaddress
import cv2
import numpy as np
from urllib.parse import urlparse, parse_qs
from datetime import datetime

# ---------------------------------
# PAGE CONFIGURATION
# ---------------------------------
st.set_page_config(
    page_title="PhishGuard AI | Citizen Cyber Shield",
    page_icon="🛡️",
    layout="wide"
)

CSV_FILE = "scam_reports.csv"

# Initialize local CSV database
if not os.path.exists(CSV_FILE):
    with open(CSV_FILE, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "Category", "Details", "Reporter"])

# ---------------------------------
# CUSTOM HACKATHON UI DESIGN
# ---------------------------------
st.markdown("""
<style>
.stApp {
    background-color: #081426;
    color: white;
}
h1, h2, h3, p, label, li {
    color: white !important;
}
.hero {
    background: linear-gradient(120deg, #0F294A, #126B83);
    padding: 32px;
    border-radius: 18px;
    text-align: center;
    margin-bottom: 22px;
    border: 1px solid #1E88E5;
}
.hero h1 { font-size: 42px; margin-bottom: 5px; }
.hero p { font-size: 17px; color: #E0F7FA !important; }
.feature {
    background: #132C4A;
    padding: 20px;
    border-radius: 13px;
    min-height: 150px;
    border-left: 4px solid #00E5FF;
}
.tip {
    background: #123832;
    padding: 14px;
    border-radius: 10px;
    margin-bottom: 10px;
    border-left: 4px solid #00E676;
}
.stButton button {
    background-color: #FF5252;
    color: white;
    border-radius: 9px;
    border: none;
    font-weight: bold;
    padding: 8px 18px;
}
.stButton button:hover {
    background-color: #FF1744;
}
footer { visibility: hidden; }
</style>
""", unsafe_allow_html=True)

# ---------------------------------
# SIDEBAR & NAVIGATION
# ---------------------------------
st.sidebar.title("🛡️ PhishGuard AI")
st.sidebar.caption("Complete Citizen Fraud Protection")

page = st.radio(
    "Navigation",
    [
        "Home",
        "Scan Website",
        "Check Message",
        "QR & UPI Guard",
        "Scam Panic Check",
        "Emergency Help",
        "Report Scam"
    ],
    horizontal=True,
    label_visibility="collapsed"
)

st.sidebar.divider()
st.sidebar.subheader("🚨 Lost Money? Act in 1 Hour!")
st.sidebar.error(
    "**1. Call `1930`** (National Cybercrime Helpline - 24x7)\n\n"
    "**2. Visit:** [cybercrime.gov.in](https://cybercrime.gov.in)\n\n"
    "**3. Call your bank** immediately to freeze UPI/cards."
)
st.sidebar.info(
    "**Golden Rule:** You NEVER enter a UPI PIN or scan a QR code to *receive* money."
)

# ---------------------------------
# CORE AI / HEURISTIC URL ENGINE
# ---------------------------------
def analyze_url(url):
    score = 0
    reasons = []
    try:
        if not re.match(r"^https?://", url.strip(), re.I):
            url = "https://" + url.strip()

        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return None, ["Invalid website address."]

        host_lower = hostname.lower()

        if parsed.scheme != "https":
            score += 20
            reasons.append("Insecure HTTP connection (missing SSL/HTTPS encryption).")

        try:
            ipaddress.ip_address(hostname)
            score += 35
            reasons.append("Uses a raw IP address instead of a registered domain name.")
        except ValueError:
            pass

        suspicious_words = [
            "login", "verify", "account", "bank", "secure", "update",
            "free", "gift", "prize", "claim", "password", "wallet", "kyc", "refund", "reward"
        ]
        found_words = [w for w in suspicious_words if w in host_lower]
        if found_words:
            score += min(25, len(found_words) * 8)
            reasons.append("Deceptive bait keywords in domain: " + ", ".join(found_words))

        popular_brands = ["sbi", "hdfc", "icici", "axis", "paytm", "phonepe", "gpay", "amazon", "flipkart", "irctc", "aadhaar", "epfo", "uidai"]
        official_domains = {
            "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "icicibank.com",
            "axisbank.com", "paytm.com", "phonepe.com", "amazon.in", "amazon.com",
            "flipkart.com", "irctc.co.in", "uidai.gov.in", "epfindia.gov.in"
        }
        for brand in popular_brands:
            if brand in host_lower and not any(host_lower == d or host_lower.endswith("." + d) for d in official_domains):
                score += 40
                reasons.append(f"Brand Impersonation Alert: Mentions '{brand.upper()}' on an unofficial domain!")
                break

        risky_tlds = (".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".click", ".link", ".work", ".buzz")
        if host_lower.endswith(risky_tlds):
            score += 20
            reasons.append("Uses a high-risk domain extension frequently abused by scammers.")

        if len(url) > 90:
            score += 10
            reasons.append("Abnormally long URL designed to hide the true domain on mobile screens.")
        if "@" in url:
            score += 25
            reasons.append("Contains '@' redirect trick to mask the real destination.")
        if len(hostname.split(".")) > 4:
            score += 15
            reasons.append("Excessive subdomains used to mimic legitimate portals.")
        if "xn--" in host_lower:
            score += 25
            reasons.append("Uses Punycode homograph characters to visually spoof real domains.")

        try:
            socket.gethostbyname(hostname)
        except socket.gaierror:
            score += 15
            reasons.append("DNS Lookup Failed: Domain does not resolve (may be fake, typo, or taken down).")

        return min(score, 100), reasons
    except Exception:
        return None, ["Unable to analyze this URL."]

def display_scan_result(url):
    score, reasons = analyze_url(url)
    if score is None:
        st.error("❌ Please enter a valid website URL (e.g., https://example.com).")
        return

    c1, c2 = st.columns([1, 2])
    with c1:
        st.metric("Threat Risk Score", f"{score} / 100")
    with c2:
        st.write("**Risk Level Meter:**")
        st.progress(score / 100)

    if score < 30:
        st.success("✅ LOW RISK: No major phishing indicators detected. Always verify before entering sensitive credentials.")
    elif score < 60:
        st.warning("⚠️ MEDIUM RISK: Suspicious characteristics found. Do not enter passwords or banking details.")
    else:
        st.error("🚨 HIGH THREAT: Strong phishing/scam signature detected! Close this link immediately.")

    if reasons:
        st.subheader("🚩 Technical Threat Breakdown:")
        for r in reasons:
            st.write(f"- ⚠️ {r}")

# ---------------------------------
# 1. HOME PAGE
# ---------------------------------
if page == "Home":
    st.markdown("""
    <div class="hero">
        <h1>🛡️ PhishGuard AI</h1>
        <h2>All-in-One Citizen Cyber Fraud & Phishing Shield</h2>
        <p>Verify links, scan suspicious QR codes, check scam calls/SMS, and generate instant 1930 fraud reports.</p>
    </div>
    """, unsafe_allow_html=True)

    st.subheader("⚡ Instant Link Safety Check")
    q_col1, q_col2 = st.columns([4, 1])
    with q_col1:
        quick_url = st.text_input("Paste any link:", placeholder="Try: http://sbi-kyc-update.xyz", label_visibility="collapsed")
    with q_col2:
        quick_scan = st.button("🔎 Scan Now", use_container_width=True)

    if quick_scan:
        if quick_url.strip():
            display_scan_result(quick_url)
        else:
            st.warning("Please paste a URL first.")

    st.divider()

    report_count = 0
    if os.path.exists(CSV_FILE):
        with open(CSV_FILE, "r", encoding="utf-8") as f:
            report_count = max(0, sum(1 for _ in f) - 1)

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Protection Layers", "7-Point AI", "URL + DNS + QR + NLP")
    m2.metric("QR & UPI Guard", "Active", "Detects Receive Scams")
    m3.metric("Community Reports", f"{report_count}", "Live Threat Feed")
    m4.metric("Cyber Helpline", "1930", "24x7 Toll-Free India")

    st.divider()

    st.subheader("🛡️ How PhishGuard Keeps You Safe")
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown("""
        <div class="feature">
        <h3>🔍 Link & Spoof Scan</h3>
        <p>Catches fake bank portals, IP links, and shortened URLs before you click.</p>
        </div>
        """, unsafe_allow_html=True)
    with col2:
        st.markdown("""
        <div class="feature">
        <h3>📷 QR & UPI Shield</h3>
        <p>Inspects QR code images and UPI IDs to stop fake refund & payment traps.</p>
        </div>
        """, unsafe_allow_html=True)
    with col3:
        st.markdown("""
        <div class="feature">
        <h3>🆘 30-Sec Panic Check</h3>
        <p>Simple 3-question check if someone on a call/WhatsApp is pressuring you.</p>
        </div>
        """, unsafe_allow_html=True)
    with col4:
        st.markdown("""
        <div class="feature">
        <h3>📝 1930 Report Builder</h3>
        <p>Generates an instant formal complaint draft to freeze stolen funds fast.</p>
        </div>
        """, unsafe_allow_html=True)

    st.divider()

    st.subheader("📡 Live Community Scam Alert Feed")
    if report_count > 0:
        with open(CSV_FILE, "r", encoding="utf-8") as f:
            rows = list(csv.reader(f))[1:]
            for row in reversed(rows[-5:]):
                if len(row) >= 4:
                    st.warning(f"**[{row[0]}] {row[1]}** — `{row[2]}` *(Reported by {row[3]})*")
    else:
        st.info("No community scam reports logged yet. Use **Report Scam** to publish the first alert!")

    st.divider()

    st.header("💡 4 Golden Rules Against Online Fraud")
    tips = [
        "NEVER scan a QR code or enter your UPI PIN to receive money—PINs are ONLY for sending money.",
        "Police, CBI, Customs, or RBI NEVER conduct 'Digital Arrests' or demand money over WhatsApp/Skype video calls.",
        "NEVER install AnyDesk, TeamViewer, or RustDesk when told by a 'customer care' caller.",
        "Always check the website domain ending—official banks use .co.in or .com, never .xyz, .top, or .click."
    ]
    for tip in tips:
        st.markdown(f'<div class="tip">✅ {tip}</div>', unsafe_allow_html=True)


# ---------------------------------
# 2. DEEP WEBSITE SCANNER + UNSHORTENER
# ---------------------------------
elif page == "Scan Website":
    st.title("🔍 Deep Website & Short-Link Scanner")
    st.write("Check full website URLs or trace shortened links (`bit.ly`, `tinyurl`) to reveal where they truly lead.")

    url = st.text_input("Enter Website URL or Shortened Link", placeholder="https://example.com or https://bit.ly...")
    col_a, col_b = st.columns(2)
    with col_a:
        run_scan = st.button("🔎 Scan Website Directly", use_container_width=True)
    with col_b:
        run_unshorten = st.button("🔗 Trace Redirect & Scan", use_container_width=True)

    if run_scan:
        if not url.strip():
            st.warning("Please enter a website URL.")
        else:
            st.divider()
            display_scan_result(url)

    if run_unshorten:
        if not url.strip():
            st.warning("Please enter a shortened URL.")
        else:
            st.divider()
            try:
                target = url.strip()
                if not target.startswith(("http://", "https://")):
                    target = "https://" + target
                resp = requests.head(target, allow_redirects=True, timeout=6)
                st.info(f"**Final Destination URL:** `{resp.url}`")
                display_scan_result(resp.url)
            except Exception:
                st.error("❌ Could not trace this link. It may be invalid, offline, or blocking automated checks.")

# ---------------------------------
# 3. MESSAGE SCAM CHECKER
# ---------------------------------
elif page == "Check Message":
    st.title("📩 Suspicious SMS / WhatsApp Analyzer")
    st.write("Paste any suspicious SMS, WhatsApp forward, or email below to detect scam tactics.")
    msg = st.text_area("Paste Message Here", placeholder="e.g., Dear customer, your electricity will be disconnected tonight at 9:30 PM. Update bill at bit.ly/pay...")

    if st.button("🔍 Analyze Message"):
        if not msg.strip():
            st.warning("Please paste a message to analyze.")
        else:
            red_flags = []
            text = msg.lower()

            urgency = ["blocked", "suspended", "urgent", "immediately", "24 hours", "tonight", "expire", "kyc", "disconnected", "legal action", "arrest", "customs", "parcel"]
            lures = ["won", "lottery", "prize", "cashback", "refund", "free gift", "part-time", "work from home", "earn daily", "selected", "approve"]
            sensitive = ["otp", "pin", "cvv", "password", "aadhaar", "pan card", "bank details", "anydesk", "teamviewer", "rustdesk"]
            short_links = ["bit.ly", "tinyurl", "t.co", "goo.gl", "cutt.ly", "rb.gy", "wa.me"]

            if any(w in text for w in urgency):
                red_flags.append("Psychological Fear/Urgency: Threatens account block, disconnection, or legal arrest.")
            if any(w in text for w in lures):
                red_flags.append("Financial Bait: Promises unrealistic rewards, refunds, or easy work-from-home income.")
            if any(w in text for w in sensitive):
                red_flags.append("Credential / Remote Access Trap: Asks for OTP, PIN, ID details, or screen-sharing apps.")
            if any(s in text for s in short_links):
                red_flags.append("Hidden Link: Uses a URL shortener or WhatsApp redirect to hide the real website.")

            st.divider()
            if red_flags:
                st.error(f"🚨 HIGH SCAM RISK — Detected {len(red_flags)} Manipulation Tactic(s):")
                for flag in red_flags:
                    st.write(f"- ⚠️ {flag}")
                st.info("**Safe Action:** Delete the message, block the sender, and never call phone numbers written inside the text.")
            else:
                st.success("✅ No common scam phrases detected, though you should always verify unknown senders independently.")

# ---------------------------------
# 4. QR CODE & UPI PAYMENT GUARD
# ---------------------------------
elif page == "QR & UPI Guard":
    st.title("📷 QR Code & UPI Payment Fraud Guard")
    st.write("Inspect suspicious QR code screenshots or UPI IDs **before** opening your payment app.")

    tab1, tab2 = st.tabs(["📷 Scan QR Code Screenshot", "💳 Verify UPI ID"])

    with tab1:
        st.subheader("Upload a Screenshot of Any Suspicious QR Code")
        uploaded_qr = st.file_uploader("Upload QR Image (PNG, JPG, JPEG)", type=["png", "jpg", "jpeg"])
        if uploaded_qr is not None:
            file_bytes = np.asarray(bytearray(uploaded_qr.read()), dtype=np.uint8)
            img = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
            detector = cv2.QRCodeDetector()
            data, _, _ = detector.detectAndDecode(img)

            if data:
                st.info(f"**Decoded QR Content:** `{data}`")
                if data.lower().startswith("upi://pay"):
                    parsed_upi = urlparse(data)
                    params = parse_qs(parsed_upi.query)
                    payee_addr = params.get("pa", ["Unknown"])
                    payee_name = params.get("pn", ["Unknown"])
                    amount = params.get("am", ["Not fixed (User enters)"])

                    st.error("🚨 PAYMENT REQUEST DETECTED! Scanning this QR code will DEDUCT money from your bank account—it CANNOT credit money to you!")
                    st.write(f"- **Receiver UPI ID:** `{payee_addr}`")
                    st.write(f"- **Receiver Name:** `{payee_name}`")
                    st.write(f"- **Requested Amount:** `₹{amount}`")
                elif data.lower().startswith(("http://", "https://")):
                    st.warning("This QR code opens a website link. Running automatic security scan:")
                    display_scan_result(data)
                else:
                    st.write("Decoded plain text above. Verify carefully before acting.")
            else:
                st.error("❌ Could not detect a readable QR code in this image. Please upload a clearer, cropped screenshot.")

    with tab2:
        st.subheader("Check a UPI ID Before Sending Money")
        upi_id = st.text_input("Enter UPI ID", placeholder="e.g., refund-helpdesk@okaxis", key="upi_input")
        if st.button("✅ Check UPI Safety"):
            parts = upi_id.lower().strip().split("@")
            if len(parts) != 2 or not parts or not parts:
                st.error("❌ Invalid UPI ID format. A valid UPI ID must follow `username@bankhandle`.")
            else:
                user_part, handle = parts, parts
                scam_keywords = ["refund", "cashback", "prize", "lottery", "kyc", "support", "helpdesk", "customercare", "reward", "claim", "admin"]
                if any(k in user_part for k in scam_keywords):
                    st.error("🚨 HIGH SCAM RISK: Real banks and companies NEVER send refunds or prizes via UPI handles containing words like 'refund', 'kyc', or 'support'!")
                else:
                    st.success(f"✅ Valid UPI structure (`@{handle}`).")
                    st.warning("⚠️ Always verify the receiver's registered banking name on your UPI screen before entering your PIN.")

# ---------------------------------
# 5. INTERACTIVE 30-SECOND SCAM PANIC CHECK
# ---------------------------------
elif page == "Scam Panic Check":
    st.title("🆘 30-Second 'Am I Being Scammed?' Checker")
    st.write("On a stressful call or chat right now? Answer 3 simple questions for an instant verdict:")

    q1 = st.radio(
        "1. Is the caller/message threatening urgent action (account block, electricity cut, parcel arrest, or police/CBI case)?",
        ["No", "Yes"]
    )
    q2 = st.radio(
        "2. Are they asking you to enter a UPI PIN, share an OTP, scan a QR code to 'receive' money, or pay a 'registration/customs fee'?",
        ["No", "Yes"]
    )
    q3 = st.radio(
        "3. Are they asking you to stay on video call or install an app like AnyDesk, TeamViewer, or RustDesk?",
        ["No", "Yes"]
    )

    if st.button("🛡️ Get Instant Safety Verdict"):
        st.divider()
        if q1 == "Yes" or q2 == "Yes" or q3 == "Yes":
            st.error("🚨 STOP IMMEDIATELY — YOU ARE TARGETED BY A SCAMMER!")
            st.markdown("""
            ### Do These 3 Things Right Now:
            1. **Hang up the call / close the chat immediately.** Do not argue or explain.
            2. **Do NOT transfer any money, share OTPs, or install any app.**
            3. **Verify independently:** Call your bank or family member directly using a trusted number.
            """)
        else:
            st.success("✅ No immediate high-pressure scam signs selected, but still never share OTPs, PINs, or passwords with anyone.")

# ---------------------------------
# 6. EMERGENCY HELP & 1930 REPORT GENERATOR
# ---------------------------------
elif page == "Emergency Help":
    st.title("🚨 Emergency Victim Assistance & 1930 Report Generator")
    st.write("If you or someone you know lost money to online fraud, **every minute counts**. Generate a ready-to-submit complaint draft below:")

    col1, col2 = st.columns(2)
    with col1:
        victim_name = st.text_input("Full Name", placeholder="Your Name")
        victim_phone = st.text_input("Registered Mobile Number", placeholder="98XXXXXXXX")
        bank_name = st.text_input("Your Bank / UPI App Name", placeholder="e.g., SBI / PhonePe / Google Pay")
        with col2:
            amount_lost = st.text_input("Amount Lost (₹)", placeholder="e.g., 5000")
            txn_id = st.text_input("UTR / Transaction Reference ID", placeholder="12-digit UTR number")
            fraud_summary = st.text_input("Scammer's UPI ID / Phone / Website", placeholder="e.g., fake-kyc@ybl or +91-90000XXXXX")

    if st.button("📄 Generate Official Complaint Draft"):
        if victim_name and bank_name and amount_lost:
            draft = f"""To,
The Cyber Crime Cell / Nodal Officer ({bank_name}),
National Cyber Crime Reporting Portal (1930 / cybercrime.gov.in)

Subject: Urgent Request to Freeze Fraudulent Transaction & Block Beneficiary Account (UTR: {txn_id or 'Pending'})

Respected Sir/Madam,
I, {victim_name} (Mobile: {victim_phone or 'N/A'}), wish to report an online financial fraud that occurred on {datetime.now().strftime('%d-%b-%Y')}.
An amount of Rs. {amount_lost} was fraudulently debited from my {bank_name} account via Transaction/UTR ID: {txn_id or 'Not Provided'}.
The fraudster's details (UPI ID / Phone / Link) are: {fraud_summary or 'Not Provided'}.

I kindly request you to immediately put a lien/freeze on the beneficiary account and initiate a chargeback/reversal under RBI cyber fraud guidelines.

Sincerely,
{victim_name}
Contact: {victim_phone or 'N/A'}"""
            st.success("✅ Complaint draft generated! Copy this text and submit it at **cybercrime.gov.in** or email your bank's nodal officer after calling **1930**:")
            st.code(draft, language="text")
        else:
            st.warning("Please enter at least your Name, Bank Name, and Amount Lost.")

# ---------------------------------
# 7. REPORT SCAM TO COMMUNITY FEED
# ---------------------------------
elif page == "Report Scam":
    st.title("📢 Report a Scam to the Community Database")
    st.write("Submit a suspicious link, fake UPI ID, or scam number. Your alert appears live on the **Home Screen** to protect other citizens.")

    with st.form("scam_report_form", clear_on_submit=True):
        name = st.text_input("Your Name (or 'Anonymous')")
        category = st.selectbox(
            "Scam Category",
            ["Phishing Website / Fake Bank Link", "Fake UPI / QR Payment Scam", "Digital Arrest / Fake Police Call", "Fake Electricity / KYC SMS", "Job / Lottery Scam", "Other"]
        )
        details = st.text_area("Suspicious URL, UPI ID, Phone Number, or Details", placeholder="e.g., http://fake-bank-kyc.xyz asking for OTP")
        submitted = st.form_submit_button("🚨 Publish Scam Alert")

        if submitted:
            if details.strip():
                reporter_name = name.strip() if name.strip() else "Anonymous"
                timestamp = datetime.now().strftime("%d-%b-%Y %H:%M")
                with open(CSV_FILE, mode="a", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow([timestamp, category, details.strip(), reporter_name])
                st.success("✅ Alert published! Check the Home screen's Live Community Scam Alert Feed to see it live.")
            else:
                st.warning("Please enter the suspicious URL or scam details before submitting.")
