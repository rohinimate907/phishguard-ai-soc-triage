import pandas as pd

# Load the dataset
# If your file name is different, update it here
df = pd.read_csv("emails.csv")

print("--- First 5 Rows ---")
print(df.head())

print("\n--- Dataset Info & Data Types ---")
print(df.info())

print("\n--- Class Distribution ---")
# Check how many phishing vs safe emails exist
print(df.iloc[:, -1].value_counts())

print("\n--- Missing Values Check ---")
print(df.isnull().sum())