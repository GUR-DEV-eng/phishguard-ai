 #model_training.py
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib
import re

# Load dataset (adjust path)
df = pd.read_csv('data/phishing_site_urls.csv')  # or your file name

# Assume columns: 'URL', 'Label' where Label is 'good' or 'bad'
df['Label'] = df['Label'].map({'good': 0, 'bad': 1})  # 0=safe, 1=phishing

# Feature extraction functions
def extract_features(url):
    features = {}
    features['url_length'] = len(url)
    features['has_https'] = 1 if url.startswith('https') else 0
    features['num_special'] = len(re.findall(r'[^a-zA-Z0-9]', url))
    features['num_digits'] = sum(c.isdigit() for c in url)
    features['has_ip'] = 1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0
    suspicious_words = ['login', 'verify', 'bank', 'free', 'update', 'secure', 'account']
    features['suspicious_count'] = sum(word in url.lower() for word in suspicious_words)
    return pd.Series(features)

# Apply features
print("Extracting features...")
features_df = df['URL'].apply(extract_features)
data = pd.concat([features_df, df['Label']], axis=1)

# Split
X = data.drop('Label', axis=1)
y = data['Label']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train Random Forest (good balance of speed/accuracy)
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate
preds = model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, preds))
print(classification_report(y_test, preds))

# Save model
joblib.dump(model, 'phishing_model.pkl')
print("Model saved as phishing_model.pkl")
