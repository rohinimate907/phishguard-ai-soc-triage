import re
import joblib
import numpy as np
import pandas as pd
from scipy.sparse import hstack

from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.preprocessing import StandardScaler

# 1. Load Real Data
df = pd.read_csv("real_emails.csv")

# 2. Handcrafted Cybersecurity Heuristics Extractor
def extract_security_features(texts):
    features = []
    
    # Pre-compiled security patterns
    ip_pattern = re.compile(r'http[s]?://(?:\d{1,3}\.){3}\d{1,3}')
    url_pattern = re.compile(r'https?://|www\.')
    urgency_pattern = re.compile(r'\b(urgent|immediate|suspended|action required|verify|password|security alert|unauthorized|risk)\b', re.IGNORECASE)
    financial_pattern = re.compile(r'\b(dollar|free|winner|claim|funds|bank|wire|transfer|payment|invoice)\b', re.IGNORECASE)
    
    for text in texts:
        text_str = str(text)
        length = len(text_str)
        url_count = len(url_pattern.findall(text_str))
        has_ip = 1 if ip_pattern.search(text_str) else 0
        urgency_score = len(urgency_pattern.findall(text_str))
        financial_score = len(financial_pattern.findall(text_str))
        caps_ratio = sum(1 for c in text_str if c.isupper()) / (length + 1)
        
        features.append([
            url_count,
            has_ip,
            urgency_score,
            financial_score,
            caps_ratio,
            length
        ])
        
    return np.array(features)

print("[INFO] Extracting domain security heuristics...")
X_heuristics = extract_security_features(df["email_text"])

# 3. Train-Test Split (80/20) with Stratification
X_train_text, X_test_text, X_train_heur, X_test_heur, y_train, y_test = train_test_split(
    df["email_text"],
    X_heuristics,
    df["label"],
    test_size=0.2,
    random_state=42,
    stratify=df["label"]
)

# 4. Standardize Heuristic Features
scaler = StandardScaler()
X_train_heur_scaled = scaler.fit_transform(X_train_heur)
X_test_heur_scaled = scaler.transform(X_test_heur)

# 5. Robust Sublinear TF-IDF (Prevents single token dominance)
vectorizer = TfidfVectorizer(
    max_features=5000,
    ngram_range=(1, 2),
    sublinear_tf=True,
    stop_words="english"
)
X_train_tfidf = vectorizer.fit_transform(X_train_text)
X_test_tfidf = vectorizer.transform(X_test_text)

# 6. Stack NLP Features + Heuristics
X_train_final = hstack([X_train_tfidf, X_train_heur_scaled])
X_test_final = hstack([X_test_tfidf, X_test_heur_scaled])

# 7. Regularized Logistic Regression (Balanced class weights to penalize False Negatives)
clf = LogisticRegression(C=1.5, class_weight='balanced', max_iter=1000, random_state=42)

# 8. 5-Fold Stratified Cross-Validation (Proof against overfitting)
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cv_scores = cross_val_score(clf, X_train_final, y_train, cv=cv, scoring='f1')
print(f"[CV 5-Fold F1-Score]: Mean = {cv_scores.mean()*100:.2f}% | Std = {cv_scores.std()*100:.2f}%\n")

# Fit final model
clf.fit(X_train_final, y_train)

# 9. Test Set Evaluation
y_pred = clf.predict(X_test_final)
y_prob = clf.predict_proba(X_test_final)[:, 1]

print("=== Final Out-Of-Sample Test Evaluation ===")
print(classification_report(y_test, y_pred, target_names=["Safe (Ham)", "Phishing/Spam"]))
print(f"ROC-AUC Score: {roc_auc_score(y_test, y_prob):.4f}")

# 10. Export Artifacts for Application Integration
joblib.dump(clf, "advanced_phishing_model.pkl")
joblib.dump(vectorizer, "advanced_vectorizer.pkl")
joblib.dump(scaler, "heuristic_scaler.pkl")
print("\n[SUCCESS] Production artifacts exported.")