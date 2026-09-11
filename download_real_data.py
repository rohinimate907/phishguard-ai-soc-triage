import pandas as pd

# Reliable, permanent raw mirror of the SMS/Email Security corpus (5,572 real samples)
url = "https://raw.githubusercontent.com/justmarkham/DAT8/master/data/sms.tsv"

print("Fetching authentic dataset...")
df = pd.read_csv(url, sep="\t", header=None, names=["label_raw", "email_text"])

# Map classes: ham (safe) = 0, spam/phishing = 1
df["label"] = df["label_raw"].map({"ham": 0, "spam": 1})

# Security integrity: drop exact duplicates to prevent data leakage/overfitting
df = df.drop_duplicates(subset=["email_text"])
df = df.dropna()

df.to_csv("real_emails.csv", index=False)
print(f"[SUCCESS] Saved 'real_emails.csv' with {len(df)} authentic records.")
print("\nClass breakdown:")
print(df["label"].value_counts())