import requests
from bs4 import BeautifulSoup
import tldextract
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
import joblib

# Function to check if a URL is phishing using a simple heuristic
def is_phishing(url):
    # Simple heuristic: check if the URL contains common phishing indicators
    phishing_indicators = [
        'login', 'signin', 'account', 'verify', 'update', 'secure',
        'bank', 'credit', 'paypal', 'ebay', 'amazon'
    ]
    for indicator in phishing_indicators:
        if indicator in url:
            return True
    return False

# Function to check if a URL is in a known phishing database
def check_phishing_database(url):
    # Example: Using a public API like PhishTank
    api_url = f'https://checkurl.phishtank.com/checkurl/?url={url}&format=json'
    response = requests.get(api_url)
    if response.status_code == 200:
        data = response.json()
        return data['results_in_database']
    return False

# Function to analyze the URL structure
def analyze_url_structure(url):
    extracted = tldextract.extract(url)
    domain = extracted.domain
    suffix = extracted.suffix
    # Simple heuristic: check if the domain is suspicious
    suspicious_domains = ['bit.ly', 'tinyurl.com', 'goo.gl']
    if domain in suspicious_domains or len(domain) > 20:
        return True
    return False

# Function to analyze the content of the URL
def analyze_content(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            # Simple heuristic: check for common phishing content
            phishing_content = [
                'login', 'signin', 'account', 'verify', 'update', 'secure',
                'bank', 'credit', 'paypal', 'ebay', 'amazon'
            ]
            for content in phishing_content:
                if content in soup.get_text().lower():
                    return True
            return False
    except requests.RequestException:
        return False

# Main function to scan a URL
def scan_url(url):
    if is_phishing(url):
        return "Phishing detected based on URL structure."
    if check_phishing_database(url):
        return "Phishing detected based on known phishing database."
    if analyze_url_structure(url):
        return "Phishing detected based on suspicious URL structure."
    if analyze_content(url):
        return "Phishing detected based on suspicious content."
    return "URL appears to be safe."

# Example usage
url = "https://example.com/login"
result = scan_url(url)
print(result)
