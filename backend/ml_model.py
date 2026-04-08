import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib

def generate_synthetic_data(num_samples=1500):
    np.random.seed(42)
    data = []
    
    for _ in range(num_samples):
        # 50-50 split
        is_phishing = np.random.choice([0, 1])
        
        if is_phishing == 1:
            # Phishing feature distributions
            url_length = int(np.random.normal(80, 20))
            is_long_url = 1 if url_length > 54 else 0
            has_at_symbol = np.random.choice([0, 1], p=[0.8, 0.2])
            has_ip_address = np.random.choice([0, 1], p=[0.7, 0.3])
            num_hyphens = int(np.abs(np.random.normal(1.5, 1.5)))
            has_hyphen_in_domain = 1 if num_hyphens > 0 else 0
            num_subdomains = int(np.abs(np.random.normal(2, 1.5)))
            is_https = np.random.choice([0, 1], p=[0.7, 0.3]) # Often, phishers don't have HTTPS, but some do
            has_suspicious_words = np.random.choice([0, 1], p=[0.4, 0.6])
            has_form_with_action = np.random.choice([0, 1], p=[0.3, 0.7])
            has_password_field = np.random.choice([0, 1], p=[0.3, 0.7])
            has_hidden_elements = np.random.choice([0, 1], p=[0.5, 0.5])
            label = 1
        else:
            # Legitimate feature distributions
            url_length = int(np.random.normal(35, 15))
            is_long_url = 1 if url_length > 54 else 0
            has_at_symbol = 0 
            has_ip_address = 0 
            num_hyphens = int(np.abs(np.random.normal(0.2, 0.5)))
            has_hyphen_in_domain = 1 if num_hyphens > 0 else 0
            num_subdomains = int(np.abs(np.random.normal(0.5, 0.5)))
            is_https = np.random.choice([0, 1], p=[0.1, 0.9])
            has_suspicious_words = np.random.choice([0, 1], p=[0.9, 0.1])
            has_form_with_action = np.random.choice([0, 1], p=[0.8, 0.2])
            has_password_field = np.random.choice([0, 1], p=[0.7, 0.3])
            has_hidden_elements = np.random.choice([0, 1], p=[0.9, 0.1])
            label = 0
            
        data.append({
            'url_length': max(10, url_length), # ensure > 0
            'is_long_url': is_long_url,
            'has_at_symbol': has_at_symbol,
            'has_ip_address': has_ip_address,
            'num_hyphens': num_hyphens,
            'has_hyphen_in_domain': has_hyphen_in_domain,
            'num_subdomains': num_subdomains,
            'is_https': is_https,
            'has_suspicious_words': has_suspicious_words,
            'has_form_with_action': has_form_with_action,
            'has_password_field': has_password_field,
            'has_hidden_elements': has_hidden_elements,
            'label': label
        })
        
    return pd.DataFrame(data)

def train_and_save_model():
    print("Generating dataset...")
    df = generate_synthetic_data(2000)
    
    # Ensure columns align with feature_extraction returns!
    X = df.drop('label', axis=1)
    y = df['label']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("Training Random Forest Classifier...")
    clf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    clf.fit(X_train, y_train)
    
    preds = clf.predict(X_test)
    accuracy = accuracy_score(y_test, preds)
    print(f"Model Accuracy on Synthetic Test Data: {accuracy * 100:.2f}%")
    
    print("Saving model to model.pkl...")
    joblib.dump(clf, 'model.pkl')
    print("Saving feature mappings to model_features.pkl...")
    joblib.dump(list(X.columns), 'model_features.pkl')
    
    print("Training complete!")

if __name__ == "__main__":
    train_and_save_model()
