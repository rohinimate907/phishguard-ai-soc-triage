import streamlit as st
import joblib
import re
import numpy as np
import pandas as pd
from scipy.sparse import hstack

st.set_page_config(
    page_title="PhishGuard SOC | Threat Analysis Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Polished High-Contrast SOC Styling
st.markdown("""
<style>
    /* Global Typography & Contrast */
    .stApp {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }
    
    /* Prominent Status Badges */
    .status-badge-crit {
        background-color: rgba(220, 38, 38, 0.2);
        border: 2px solid #ef4444;
        color: #fca5a5;
        padding: 10px 16px;
        border-radius: 8px;
        font-weight: 700;
        font-size: 16px;
        display: inline-block;
        margin-bottom: 12px;
    }
    
    .status-badge-safe {
        background-color: rgba(16, 185, 129, 0.2);
        border: 2px solid #10b981;
        color: #6ee7b7;
        padding: 10px 16px;
        border-radius: 8px;
        font-weight: 700;
        font-size: 16px;
        display: inline-block;
        margin-bottom: 12px;
    }

    .tag-mitre {
        background-color: #3b0764;
        border: 1px solid #a855f7;
        color: #e9d5ff;
        padding: 4px 10px;
        border-radius: 6px;
        font-size: 13px;
        font-weight: 600;
        display: inline-block;
    }

    .defanged-box {
        background-color: #111827;
        border: 1px solid #374151;
        padding: 10px;
        border-radius: 6px;
        font-family: monospace;
        color: #f87171;
    }

    .token-chip {
        background-color: #991b1b;
        color: #fef2f2;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

# 1. State Management
if "triage_history" not in st.session_state:
    st.session_state.triage_history = []
if "latest_result" not in st.session_state:
    st.session_state.latest_result = None

# 2. Pipeline Artifacts
@st.cache_resource
def load_pipeline():
    model = joblib.load("advanced_phishing_model.pkl")
    vec = joblib.load("advanced_vectorizer.pkl")
    scaler = joblib.load("heuristic_scaler.pkl")
    return model, vec, scaler

model, vectorizer, scaler = load_pipeline()

def defang_url(url: str) -> str:
    return url.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")

def parse_forensics(raw_text: str):
    ip_pattern = re.compile(r'http[s]?://(?:\d{1,3}\.){3}\d{1,3}(?:/\S*)?')
    url_pattern = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
    urgency_pattern = re.compile(r'\b(urgent|immediate|suspended|action required|verify|password|security alert|unauthorized|risk)\b', re.IGNORECASE)
    financial_pattern = re.compile(r'\b(dollar|free|winner|claim|funds|bank|wire|transfer|payment|invoice)\b', re.IGNORECASE)
    
    urls = url_pattern.findall(raw_text)
    ips = ip_pattern.findall(raw_text)
    urgency = urgency_pattern.findall(raw_text)
    finance = financial_pattern.findall(raw_text)
    length = len(raw_text)
    caps_ratio = sum(1 for c in raw_text if c.isupper()) / (length + 1)
    
    heur_vec = np.array([[
        len(urls),
        1 if len(ips) > 0 else 0,
        len(urgency),
        len(finance),
        caps_ratio,
        length
    ]])
    
    return heur_vec, {
        "urls": urls,
        "defanged_urls": [defang_url(u) for u in urls],
        "ips": ips,
        "urgency_triggers": list(set([w.lower() for w in urgency])),
        "financial_triggers": list(set([w.lower() for w in finance])),
        "caps_ratio": round(caps_ratio * 100, 2)
    }

def explain_decision(text, vectorizer, model, top_n=5):
    words = re.findall(r'\b\w+\b', text.lower())
    feature_names = vectorizer.get_feature_names_out()
    coefficients = model.coef_[0][:len(feature_names)]
    vocab = vectorizer.vocabulary_
    word_weights = []
    
    for word in set(words):
        if word in vocab:
            idx = vocab[word]
            weight = coefficients[idx]
            if weight > 0:
                word_weights.append((word, weight))
                
    word_weights.sort(key=lambda x: x[1], reverse=True)
    return word_weights[:top_n]

# 3. Form Input
st.title("🛡️ PhishGuard Enterprise: SOC Threat Triage Gateway")
st.markdown("Automated Email Payload Inspection, IOC Extraction & Explainable AI (XAI) Attribution.")

with st.form("triage_form", clear_on_submit=False):
    raw_email = st.text_area(
        "Email Content / Raw Payload:",
        height=140,
        placeholder="Paste full email body or headers here to scan..."
    )
    submitted = st.form_submit_button("Run Threat Analysis", type="primary", use_container_width=True)

if submitted and raw_email.strip():
    heur_vec, meta = parse_forensics(raw_email)
    heur_scaled = scaler.transform(heur_vec)
    text_tfidf = vectorizer.transform([raw_email])
    
    X_input = hstack([text_tfidf, heur_scaled])
    prob_malicious = model.predict_proba(X_input)[0][1] * 100
    
    if meta["ips"]:
        prob_malicious = max(prob_malicious, 89.0)
        
    severity = "CRITICAL" if prob_malicious >= 70 else ("MEDIUM" if prob_malicious >= 40 else "SAFE")
    technique = "T1566.002 (Spearphishing Link)" if meta["urls"] else "T1566 (Phishing)"
    top_explanations = explain_decision(raw_email, vectorizer, model)
    
    scan_record = {
        "Timestamp": pd.Timestamp.now().strftime("%H:%M:%S"),
        "Verdict": severity,
        "Risk Score": f"{prob_malicious:.1f}%",
        "IOCs Found": len(meta["urls"]) + len(meta["ips"]),
        "Email Snippet": raw_email[:50] + "..."
    }
    st.session_state.triage_history.insert(0, scan_record)
    
    st.session_state.latest_result = {
        "raw_email": raw_email,
        "severity": severity,
        "prob_malicious": prob_malicious,
        "technique": technique,
        "meta": meta,
        "top_explanations": top_explanations
    }

# 4. Sidebar Telemetry
with st.sidebar:
    st.header("⚡ SOC Operations")
    st.caption("Active Session Telemetry")
    
    total_scans = len(st.session_state.triage_history)
    flagged = sum(1 for item in st.session_state.triage_history if item["Verdict"] in ["CRITICAL", "MEDIUM"])
    
    st.metric("Total Scanned", total_scans)
    st.metric("Threats Flagged", flagged)
    
    st.divider()
    st.markdown("**Framework Alignment:**")
    st.markdown("- **MITRE ATT&CK:** T1566 (Phishing)")
    st.markdown("- **Cyber Kill Chain:** Phase 3 (Delivery)")
    
    if total_scans > 0:
        st.divider()
        if st.button("Clear History", use_container_width=True):
            st.session_state.triage_history = []
            st.session_state.latest_result = None
            st.rerun()

# 5. Output Card
if st.session_state.latest_result:
    res = st.session_state.latest_result
    st.divider()
    
    c1, c2, c3, c4 = st.columns([2, 1, 1, 1])
    with c1:
        st.subheader("Analysis Verdict")
        if res["severity"] == "CRITICAL":
            st.markdown('<div class="status-badge-crit">🚨 MALICIOUS / PHISHING THREAT DETECTED</div>', unsafe_allow_html=True)
        elif res["severity"] == "MEDIUM":
            st.warning("⚠️ SUSPICIOUS PAYLOAD (MANUAL REVIEW NEEDED)")
        else:
            st.markdown('<div class="status-badge-safe">✅ LEGITIMATE / SAFE EMAIL</div>', unsafe_allow_html=True)
            
        st.progress(int(res["prob_malicious"]))
        st.caption(f"Calculated Malicious Probability: **{res['prob_malicious']:.2f}%**")
        
    with c2:
        st.metric("Threat Severity", res["severity"])
        st.markdown(f'<span class="tag-mitre">{res["technique"]}</span>', unsafe_allow_html=True)
        
    with c3:
        st.metric("Extracted Links", len(res["meta"]["urls"]))
        
    with c4:
        st.metric("Direct IP Targets", len(res["meta"]["ips"]))

    # Detailed Tabs
    st.subheader("Detailed Forensic Findings")
    t_xai, t_ioc, t_report = st.tabs(["🧠 Explainable AI (Attribution)", "🌐 Extracted IOCs", "📋 Incident Report"])
    
    with t_xai:
        st.markdown("**Tokens Triggering Phishing Confidence:**")
        if res["top_explanations"]:
            t_cols = st.columns(len(res["top_explanations"]))
            for idx, (word, weight) in enumerate(res["top_explanations"]):
                with t_cols[idx]:
                    st.metric(f"Token '{word}'", f"+{weight:.2f}")
        else:
            st.info("No single token strongly triggered suspicion; verdict derived from baseline text patterns and heuristics.")

        highlighted_text = res["raw_email"]
        for word, _ in res["top_explanations"]:
            pattern = re.compile(rf'\b({re.escape(word)})\b', re.IGNORECASE)
            highlighted_text = pattern.sub(r'<span class="token-chip">\1</span>', highlighted_text)
            
        st.markdown(f"**Payload with Detected Suspicious Tokens Highlighted:**")
        st.markdown(f"> {highlighted_text}", unsafe_allow_html=True)

    with t_ioc:
        if res["meta"]["defanged_urls"]:
            st.markdown("**Defanged Hyperlinks (Safe to inspect):**")
            for u in res["meta"]["defanged_urls"]:
                st.code(u, language="text")
        else:
            st.info("No outbound URLs identified in payload.")
            
        if res["meta"]["ips"]:
            st.error("⚠️ Raw IP Addresses identified in URLs:")
            for ip in res["meta"]["ips"]:
                st.code(ip, language="text")

    with t_report:
        st.markdown("**SIEM Event Payload (JSON):**")
        st.json({
            "event": "EMAIL_TRIAGE_LOG",
            "timestamp": pd.Timestamp.now().isoformat(),
            "verdict": res["severity"],
            "risk_score_percent": round(res["prob_malicious"], 2),
            "mitre_technique": res["technique"],
            "urgency_triggers": res["meta"]["urgency_triggers"],
            "financial_triggers": res["meta"]["financial_triggers"],
            "iocs": res["meta"]["defanged_urls"] + res["meta"]["ips"]
        })

# 6. Audit Table
if st.session_state.triage_history:
    st.divider()
    st.subheader("📜 Session Triage Audit Log")
    st.dataframe(pd.DataFrame(st.session_state.triage_history), use_container_width=True, hide_index=True)