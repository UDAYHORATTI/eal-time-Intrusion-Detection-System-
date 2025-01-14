# eal-time-Intrusion-Detection-System-
This project focuses on real-time log monitoring and alerting for detecting intrusion attempts using Natural Language Processing (NLP) and Machine Learning. It uses log data from security appliances (like firewalls, IDS/IPS), processes the logs to extract potential security threats
import pandas as pd
import numpy as np
import re
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder
import time

# Sample logs (to be replaced with actual data in production)
logs = [
    "2025-01-14 08:00:12 Firewall Deny Access to IP 192.168.1.1 due to suspicious activity",
    "2025-01-14 08:05:22 IDS Alert: Potential SQL Injection attempt detected from IP 192.168.1.2",
    "2025-01-14 08:07:10 Firewall Allow Access from IP 192.168.1.3",
    "2025-01-14 08:10:30 IDS Alert: Malicious File Upload detected from IP 192.168.1.4",
    "2025-01-14 08:12:00 Firewall Deny Access to IP 192.168.1.5 due to port scanning",
    "2025-01-14 08:15:45 IDS Alert: DDoS Attack detected from IP 192.168.1.6",
    "2025-01-14 08:18:00 Firewall Allow Access from IP 192.168.1.7",
    "2025-01-14 08:20:30 IDS Alert: Possible Brute Force Attack detected from IP 192.168.1.8"
]

# Simulating incoming logs (real-time ingestion)
def ingest_logs():
    for log in logs:
        yield log
        time.sleep(2)  # simulate real-time log ingestion

# Log Preprocessing
def preprocess_logs(log_data):
    # Remove unwanted characters (non-alphanumeric characters, etc.)
    cleaned_logs = re.sub(r'[^A-Za-z0-9\s]', '', log_data)
    return cleaned_logs

# Feature Extraction: Using TF-IDF Vectorizer to convert log messages into numerical features
def extract_features(log_messages):
    vectorizer = TfidfVectorizer(stop_words='english')
    X = vectorizer.fit_transform(log_messages)
    return X, vectorizer

# Prepare Data for Training (Simulated for demonstration)
training_logs = [
    "Suspicious activity detected in packet capture",
    "DDoS attack detected from IP 192.168.1.2",
    "SQL Injection attempt in web application",
    "Firewall rule violation by IP 192.168.1.3",
    "Normal login attempt from IP 192.168.1.4",
    "File transfer succeeded from trusted source",
    "Malware detected in network traffic",
    "Port scanning detected from IP 192.168.1.5"
]

# Labels for training (Benign or Malicious)
labels = ["Malicious", "Malicious", "Malicious", "Malicious", "Benign", "Benign", "Malicious", "Malicious"]

# Prepare training data and labels
X_train, vectorizer = extract_features(training_logs)
le = LabelEncoder()
y_train = le.fit_transform(labels)

# Train Random Forest classifier
clf = RandomForestClassifier()
clf.fit(X_train, y_train)

# Real-time log monitoring function
def real_time_detection(log_generator):
    for log in log_generator:
        # Preprocess and classify each log
        preprocessed_log = preprocess_logs(log)
        X_new = vectorizer.transform([preprocessed_log])
        prediction = clf.predict(X_new)
        label = le.inverse_transform(prediction)[0]

        # Alerting mechanism (display an alert for malicious activity)
        if label == "Malicious":
            print(f"ALERT! Malicious activity detected: {log}")
        else:
            print(f"Normal Activity: {log}")

# Simulate real-time log monitoring and detection
real_time_detection(ingest_logs())
