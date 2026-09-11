Markdown
# 🛡️ PhishGuard: Enterprise AI Email Threat Triage & SOC Forensics Gateway

[![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://phishguard-ai-soc-triage-lcmwy3qj3sjjsv5vy2ukn5.streamlit.app/)
![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg?style=flat&logo=python)
![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-F1--Score%200.87-orange.svg?style=flat&logo=scikit-learn)
![Security-Domain](https://img.shields.io/badge/MITRE%20ATT%26CK-T1566.002-red.svg?style=flat)
![Status](https://img.shields.io/badge/Deployment-Live-brightgreen.svg?style=flat)

> **Live Production Gateway:** [https://phishguard-ai-soc-triage-lcmwy3qj3sjjsv5vy2ukn5.streamlit.app/](https://phishguard-ai-soc-triage-lcmwy3qj3sjjsv5vy2ukn5.streamlit.app/)

---

## 📌 Executive Overview

PhishGuard is an automated tier-1 **Security Operations Center (SOC) triage engine** engineered to bridge machine learning text classification with domain-specific cybersecurity threat heuristics.

Standard spam filters fail to detect evasive credential harvesting and spearphishing campaigns because they treat emails as generic natural language text. PhishGuard addresses this by combining **sublinear TF-IDF n-gram vectorization** with **6 domain heuristic extractors** (direct IPv4 targeting, URL counts, lexical coercion/urgency scores, financial keywords, and casing anomalies). 

To eliminate the "black-box" nature of AI in security environments, PhishGuard integrates an **Explainable AI (XAI)** attribution layer that exposes feature weights per token, automatically defangs Indicators of Compromise (IOCs), and exports structured JSON incident payloads for direct SIEM/SOAR ingestion.

---

<!-- DASHBOARD PREVIEW SCREENSHOT -->

<img width="1917" height="900" alt="image" src="https://github.com/user-attachments/assets/e577cc5a-7bc0-4a53-8e8f-b8f228802a1a" />


*Figure 1: High-contrast SOC Threat Triage Console showing live incident classification, XAI token attribution, and IOC defanging.*

---

##  Threat Framework Alignment

PhishGuard maps incoming threats directly to standard cyber defense taxonomies:

* **MITRE ATT&CK Matrix:**
  * **Tactic:** Initial Access (`TA0001`)
  * **Technique:** Phishing (`T1566`)
  * **Sub-techniques:** 
    * `T1566.001` — Spearphishing Attachment
    * `T1566.002` — Spearphishing Link
* **Cyber Kill Chain:** Phase 3 — **Delivery**
* **SOC Automation:** Tier-1 triage alert reduction and automatic containment artifact generation.

---

## 🏗️ System Architecture

The pipeline processes raw email content through parallel feature extraction tracks before unified inference:

[Raw Email / MIME Stream]
│
├───► Track A: NLP Processing
│        └── Sublinear TF-IDF (1-2 N-Grams, 5000 Features) ──┐
│                                                             ▼
└───► Track B: Cybersecurity Heuristics Extractor       [Feature Stacking]
├── Direct IPv4 Link Detection                  (scipy.sparse.hstack)
├── Hyperlink Pattern Extraction                     │
├── Urgency & Social Engineering Heuristics          ▼
├── Financial / Credential Harvesting Cues     [Regularized Classifier]
├── Capitalization Ratio Analysis               (Logistic Regression L2)
└── StandardScaler Normalization ────────────────────┤
▼
[Triage Engine Output]
├── Threat Verdict & Score
├── XAI Token Attribution
├── Defanged IOC Feed
└── SIEM Incident JSON


---

## 🔬 Explainable AI (XAI) & Security Features

* **White-Box Token Attribution:** Uses linear decision coefficients to extract exact per-token positive weights, highlighting words (`urgent`, `verify`, `claim`, `wire`) driving the malicious verdict.
* **Automated IOC Defanging:** Automatically sanitizes extracted URLs (`hxxp://...`, `domain[.]com`) to prevent accidental execution by security analysts during manual triage.
* **Adversarial Heuristic Overrides:** Flags raw IPv4 addresses used as hyperlink destinations (`http://192.168.1.1/...`) as severe adversary evasion attempts.
* **State-Preserved Incident Logging:** Maintains an in-memory session audit trail, enabling analysts to process multiple payloads without data loss.
* **SIEM/SOAR Export:** Generates standardized JSON telemetry containing timestamped verdicts, extracted IOCs, and MITRE metadata for quick security ticketing.

---

## 📊 Benchmark & Evaluation Results

Trained and cross-validated against authentic, non-duplicated security corpora using **5-Fold Stratified Cross-Validation**:

| Metric | Benchmark Score | Operational Significance |
| :--- | :--- | :--- |
| **ROC-AUC Score** | **0.9872** | High discriminative power across variable confidence thresholds. |
| **Phishing Precision** | **0.87** | Minimizes False Positives to avoid operational alert fatigue. |
| **Phishing Recall** | **0.88** | Minimizes False Negatives (critical payloads missed). |
| **Overall Accuracy** | **97.00%** | Robust generalization on unseen out-of-sample data. |

---

<!-- FORENSIC EVIDENCE SCREENSHOT -->


<img width="1917" height="831" alt="image" src="https://github.com/user-attachments/assets/1e61bad5-8f1f-4e0d-bb09-8ea44e0b735e" />


*Figure 2: Forensic indicator breakdown, defanged network artifacts, and explainable feature weights.*

---

## 📁 Repository Structure

```plaintext
phishguard-ai-soc-triage/
├── .streamlit/
│   └── config.toml               # Native high-contrast SOC dark theme configuration
├── advanced_phishing_model.pkl   # Serialized regularized classifier
├── advanced_vectorizer.pkl       # Fitted sublinear TF-IDF vectorizer
├── heuristic_scaler.pkl          # Fitted StandardScaler for heuristic features
├── train_advanced.py             # Feature extraction and model training pipeline
├── download_real_data.py         # Data collection and deduplication script
├── app.py                        # Streamlit SOC triage web application
├── requirements.txt              # Production dependency specifications
└── README.md                     # Project documentation
🚀 Local Installation & Setup
Clone the Repository:

Bash
git clone [https://github.com/](https://github.com/)<YOUR-USERNAME>/phishguard-ai-soc-triage.git
cd phishguard-ai-soc-triage
Create and Activate a Virtual Environment:

Bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS / Linux
python3 -m venv venv
source venv/bin/activate
Install Dependencies:

Bash
pip install -r requirements.txt
Launch the Triage Console:

Bash
streamlit run app.py
Open http://localhost:8501 in your browser.
