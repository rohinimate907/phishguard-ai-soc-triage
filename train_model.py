import pandas as pd
import numpy as np
import re
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

# 1. Load Data
df = pd.read_csv("emails.csv")

# 2. Encode Labels: Phishing = 1, Safe = 0
df["label"] = df["Email Type"].map({"Phishing Email": 1, "Safe Email": 0})

# 3. Text Preprocessing Function
def clean_text(text):
    text = str(text).lower()
    # Normalize URLs to a common token
    text = re.sub(r'https?://\S+|www\.\S+', 'httpaddr', text)
    # Normalize currency symbols and numbers
    text = re.sub(r'[$£€]', 'dollar', text)
    text = re.sub(r'\d+', 'number', text)
    # Remove special characters
    text = re.sub(r'[^\w\s]', ' ', text)
    return text

df["cleaned_text"] = df["Email Text"].apply(clean_text)

# 4. Train-Test Split (80% Training, 20% Testing)
X_train, X_test, y_train, y_test = train_test_split(
    df["cleaned_text"], 
    df["label"], 
    test_size=0.2, 
    random_state=42, 
    stratify=df["label"]
)

# 5. TF-IDF Vectorization (Extracting 1-gram and 2-gram text patterns)
vectorizer = TfidfVectorizer(max_features=3000, ngram_range=(1, 2))
X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

# 6. Train Random Forest Classifier
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train_vec, y_train)

# 7. Evaluate the Model
y_pred = model.predict(X_test_vec)

print("=== Evaluation Metrics ===")
print(f"Accuracy: {accuracy_score(y_test, y_pred) * 100:.2f}%\n")
print("Classification Report:")
print(classification_report(y_test, y_pred, target_names=["Safe Email", "Phishing Email"]))

# 8. Save the Trained Model and Vectorizer for the UI
joblib.dump(model, "phishing_model.pkl")
joblib.dump(vectorizer, "tfidf_vectorizer.pkl")
print("\n[SUCCESS] Model and vectorizer saved as 'phishing_model.pkl' and 'tfidf_vectorizer.pkl'!")