import re
from urllib.parse import urlparse
import tldextract
import requests
from bs4 import BeautifulSoup
import socket

def extract_features(url):
    features = {}
    
    # Clean URL format
    if not re.match(r"^https?", url):
        url = "http://" + url
        
    try:
        parsed_url = urlparse(url)
        extracted_domain = tldextract.extract(url)
    except:
        return None

    domain = f"{extracted_domain.domain}.{extracted_domain.suffix}"
    
    # 1. URL Length (Phishing usually has long URLs)
    features['url_length'] = len(url)
    features['is_long_url'] = 1 if len(url) > 54 else 0
    
    # 2. Presence of @ Symbol
    features['has_at_symbol'] = 1 if '@' in url else 0
    
    # 3. IP Address in URL
    ip_pattern = re.compile(
        r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.'
        r'([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\b)|'
        r'((0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\b)'
        r'(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}'
    )
    features['has_ip_address'] = 1 if ip_pattern.search(domain) else 0
    
    # 4. Number of hyphens in domain
    features['num_hyphens'] = domain.count('-')
    features['has_hyphen_in_domain'] = 1 if '-' in domain else 0
    
    # 5. Number of subdomains
    subdomain = extracted_domain.subdomain
    num_dots = subdomain.count('.') if subdomain else 0
    features['num_subdomains'] = num_dots + 1 if subdomain else 0
    
    # 6. HTTP vs HTTPS
    features['is_https'] = 1 if parsed_url.scheme == 'https' else 0
    
    # 7. Suspicious Words in URL
    suspicious_words = ['secure', 'account', 'webscr', 'login', 'ebayisapi', 'signin', 'banking', 'confirm']
    features['has_suspicious_words'] = 1 if any(word in url.lower() for word in suspicious_words) else 0

    # Page Content Features
    features['has_form_with_action'] = 0
    features['has_hidden_elements'] = 0
    features['has_password_field'] = 0
    
    try:
        # Increase timeout slightly, fake user-agent to bypass basic blocks
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(url, timeout=3, headers=headers)
        
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Form actions empty or pointing elsewhere
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                if not action or '#' in action or action.startswith('mailto:') or action.startswith('http'):
                    features['has_form_with_action'] = 1
                    break
                    
            # Check for password fields
            if soup.find('input', type='password'):
                features['has_password_field'] = 1
                
            # Check hidden elements (often used to obscure phishing templates)
            hidden_elements = soup.find_all(style=re.compile(r'display:\s*none|visibility:\s*hidden', re.I))
            if len(hidden_elements) > 2:
                features['has_hidden_elements'] = 1
                
    except Exception as e:
        # Request failed (common for bad or unreachable URLs)
        pass

    return features
