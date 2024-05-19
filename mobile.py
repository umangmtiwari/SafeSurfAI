import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import re
import socket
import whois
from datetime import datetime
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib

chat_id = 958963110

# Function to fetch latest message from Telegram
def fetch_latest_message():
    url = "https://api.telegram.org/bot6688846135:AAHCUfRebuW17I8vFopt5VXAgrifbbjAD-k/getUpdates"  # Replace <YOUR_BOT_TOKEN> with your actual bot token
    response = requests.get(url)
    data = response.json()
    if data["ok"]:
        if data["result"]:
            latest_message = data["result"][-1]["message"]["text"]
            return latest_message
        else:
            print("No new messages")
            return None
    else:
        print("Error occurred:", data["description"])
        return None

# Function to send message to Telegram
def send_message(chat_id, message):
    url = f"https://api.telegram.org/bot6688846135:AAHCUfRebuW17I8vFopt5VXAgrifbbjAD-k/sendMessage?chat_id={chat_id}&text={message}"  # Replace <YOUR_BOT_TOKEN> with your actual bot token
    response = requests.get(url)
    print("Message sent successfully:", response.ok)

# Function to check if a domain is an IP address
def check_using_ip(url):
    parsed_url = urlparse(url)
    return 1 if parsed_url.hostname.replace('.', '').isnumeric() else -1

# Function to check if the URL is long
def check_long_url(url, threshold=54):
    return 1 if len(url) >= threshold else -1


# Add other functions here...
# Function to check if the URL is short (e.g., bit.ly)
def check_short_url(url):
    parsed_url = urlparse(url)
    short_domains = ["bit.ly", "goo.gl", "t.co"]
    return 1 if parsed_url.hostname in short_domains else -1

# Function to check if "@" is in the URL
def check_symbol_at(url):
    return 1 if "@" in url else -1

# Function to check if the URL contains "//"
def check_redirecting(url):
    return 1 if "//" in url else -1

# Function to check if "-" is in the domain name
def check_prefix_suffix(url):
    parsed_url = urlparse(url)
    return -1 if "-" in parsed_url.netloc else 1

# Function to count the number of subdomains
def count_subdomains(url):
    parsed_url = urlparse(url)
    subdomain_count = parsed_url.netloc.count('.') - 1
    if subdomain_count == 0:
        return -1
    elif subdomain_count == 1:
        return 0
    else:
        return 1

# Function to check if the URL uses HTTPS
def check_https(url):
    parsed_url = urlparse(url)
    return 1 if parsed_url.scheme == 'https' else -1

# Function to check if a favicon is present on the website
def check_favicon(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        favicon_tags = soup.find_all("link", rel=lambda value: value and value.lower() == "icon")
        return 1 if favicon_tags else -1
    except Exception as e:
        print("Error in fetching favicon:", e)
        return -1

# Function to check if a non-standard port is used in the URL
def check_non_std_port(url):
    parsed_url = urlparse(url)
    return 1 if parsed_url.port and parsed_url.port not in [80, 443] else -1

# Function to check if the domain portion of the URL uses HTTPS
def check_https_domain_url(url):
    parsed_url = urlparse(url)
    return 1 if "https" in parsed_url.netloc else -1

# Function to check if less than 22% of the requests URLs are from the same domain
def check_request_url(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        total_urls = 0
        same_domain_urls = 0
        parsed_url = urlparse(url)
        for tag in soup.find_all(['a', 'img', 'script', 'link']):
            link = tag.get('href') or tag.get('src')
            if not link:
                continue
            total_urls += 1
            if urlparse(link).netloc == parsed_url.netloc:
                same_domain_urls += 1
        return 1 if total_urls > 0 and same_domain_urls / total_urls < 0.22 else -1
    except Exception as e:
        print("Error in fetching and parsing HTML content:", e)
        return -1

# Function to check the number of anchor URLs
def check_anchor_url(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        total_anchors = 0
        same_domain_anchors = 0
        parsed_url = urlparse(url)
        for tag in soup.find_all('a'):
            link = tag.get('href')
            if not link:
                continue
            total_anchors += 1
            if urlparse(link).netloc == parsed_url.netloc:
                same_domain_anchors += 1
        if total_anchors == 0:
            return 0
        ratio = same_domain_anchors / total_anchors
        if ratio == 0:
            return -1
        elif ratio < 0.31:
            return 0
        else:
            return 1
    except Exception as e:
        print("Error in fetching and parsing HTML content:", e)
        return 0

# Function to check if there are links in script tags
def check_links_in_script_tags(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        script_tags = soup.find_all('script')
        for tag in script_tags:
            if tag.get('src') and urlparse(tag.get('src')).netloc == urlparse(url).netloc:
                return 1
        return -1
    except Exception as e:
        print("Error in checking links in script tags:", e)
        return 0

# Function to calculate the domain registration length
def calculate_domain_reg_len(url):
    try:
        domain = urlparse(url).netloc
        whois_info = whois.whois(domain)
        creation_date = whois_info.creation_date
        expiration_date = whois_info.expiration_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        domain_age = (expiration_date - creation_date).days
        return 1 if domain_age / 365 > 1 else -1
    except Exception as e:
        print("Error in calculating DomainRegLen:", e)
        return -1

# Function to check if the website is indexed by Google
def check_google_index(url):
    try:
        response = requests.get(f"https://www.google.com/search?q=site:{url}")
        return 1 if response.status_code == 200 and "did not match any documents" not in response.text else -1
    except Exception as e:
        print("Error in checking Google Index:", e)
        return -1

# Function to check the PageRank of the website
def check_page_rank(url):
    try:
        response = requests.get(f"https://www.google.com/search?q=info:{url}")
        return 1 if response.status_code == 200 and url in response.text else -1
    except Exception as e:
        print("Error in checking PageRank:", e)
        return -1

# Function to check if DNS records exist
def check_dns_records(url):
    try:
        domain = urlparse(url).netloc
        records = socket.getaddrinfo(domain, None)
        return 1 if records else -1
    except Exception as e:
        print("Error in checking DNS records:", e)
        return -1

# Function to check if the website uses popup windows
def check_using_popup_window(url):
    try:
        response = requests.get(url)
        popup_script_pattern = re.compile(r'window\.open\(|window\.showModalDialog\(')
        return 1 if popup_script_pattern.search(response.text) else -1
    except Exception as e:
        print("Error in checking popup window usage:", e)
        return -1

# Function to check if right-click is disabled on the website
def check_disable_right_click(url):
    try:
        response = requests.get(url)
        right_click_disabled_pattern = re.compile(r'oncontextmenu\s*=\s*"return false"')
        return 1 if right_click_disabled_pattern.search(response.text) else -1
    except Exception as e:
        print("Error in checking right-click disable:", e)
        return -1

# Function to check if StatusBarCust is enabled on the website
def check_status_bar_cust(url):
    try:
        response = requests.get(url)
        status_bar_cust_pattern = re.compile(r'status\s*=\s*"no"')
        return -1 if status_bar_cust_pattern.search(response.text) else 1
    except Exception as e:
        print("Error in checking StatusBarCust:", e)
        return -1

# Function to check if WebsiteForwarding is enabled on the website
def check_website_forwarding(url):
    try:
        response = requests.get(url, allow_redirects=False)
        return 1 if 300 <= response.status_code < 400 else -1
    except Exception as e:
        print("Error in checking website forwarding:", e)
        return -1

# Function to check the age of the domain
def check_age_of_domain(url):
    try:
        domain = urlparse(url).netloc
        whois_info = whois.whois(domain)
        creation_date = whois_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        age_in_days = (datetime.now() - creation_date).days
        return 1 if age_in_days < 30 else -1
    except Exception as e:
        print("Error in checking Age of Domain:", e)
        return -1

# Function to check if there is a server form handler
def check_server_form_handler(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        form_tags = soup.find_all('form')
        for tag in form_tags:
            if tag.get('method') == 'post' or tag.get('enctype') == 'multipart/form-data':
                return 1
        return -1
    except Exception as e:
        print("Error in checking ServerFormHandler:", e)
        return 0

# Function to check if the URL is abnormal
def check_abnormal_url(url):
    try:
        # Check for common phishing indicators in the URL
        if "login" in url.lower() or "signin" in url.lower() or "account" in url.lower():
            return 1
        else:
            return -1
    except Exception as e:
        print("Error in checking AbnormalURL:", e)
        return -1

# Function to check if there is iframe redirection
def check_iframe_redirection(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        iframe_tags = soup.find_all('iframe')
        for tag in iframe_tags:
            if tag.get('src') and tag.get('src') != url:
                return 1
        return -1
    except Exception as e:
        print("Error in checking IframeRedirection:", e)
        return -1

# Function to check if the website provides statistical reports
def check_stats_report(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        if soup.find('a', string=re.compile(r'(statistics|stats|report)', flags=re.IGNORECASE)):
            return 1
        return -1
    except Exception as e:
        print("Error in checking StatsReport:", e)
        return -1

# Function to check if the website contains an email address in the "info" section
def check_info_email(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        info_section = soup.find(string=re.compile(r'(info|about|contact)', flags=re.IGNORECASE))
        if info_section:
            email = re.findall(r'[\w\.-]+@[\w\.-]+', info_section)
            if email:
                return 1
        return -1
    except Exception as e:
        print("Error in checking InfoEmail:", e)
        return -1

# Function to count the number of links pointing to the page
def check_links_pointing_to_page(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = soup.find_all('a')
        count = 0
        for link in links:
            href = link.get('href')
            if href and url in href:
                count += 1
        return count
    except Exception as e:
        print("Error in checking LinksPointingToPage:", e)
        return -1

def extract_features(url):
    features = {
        "UsingIP": check_using_ip(url),
        "LongURL": check_long_url(url),
        "ShortURL": check_short_url(url),
        "Symbol@": check_symbol_at(url),
        "Redirecting//": check_redirecting(url),
        "PrefixSuffix-": check_prefix_suffix(url),
        "SubDomains": count_subdomains(url),
        "HTTPS": check_https(url),
        "DomainRegLen": calculate_domain_reg_len(url),
        "Favicon": check_favicon(url),
        "NonStdPort": check_non_std_port(url),
        "HTTPSDomainURL": check_https_domain_url(url),
        "RequestURL": check_request_url(url),
        "AnchorURL": check_anchor_url(url),
        "LinksInScriptTags": check_links_in_script_tags(url),
        "ServerFormHandler": check_server_form_handler(url),
        "InfoEmail": check_info_email(url),
        "AbnormalURL": check_abnormal_url(url),
        "WebsiteForwarding": check_website_forwarding(url),
        "StatusBarCust": check_status_bar_cust(url),
        "DisableRightClick": check_disable_right_click(url),
        "UsingPopupWindow": check_using_popup_window(url),
        "IframeRedirection": check_iframe_redirection(url),
        "AgeofDomain": check_age_of_domain(url),
        "DNSRecording": check_dns_records(url),
        "PageRank": check_page_rank(url),
        "GoogleIndex": check_google_index(url),
        "LinksPointingToPage": check_links_pointing_to_page(url),
        "StatsReport": check_stats_report(url)
    }
    return features



# Load the model
df = pd.read_csv('phishing.csv')
if 'Index' in df.columns:
    df = df.drop(columns=['Index'])
X = df.drop(columns=['class'])
y = df['class']
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.3, random_state=42)
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

def main():
    latest_message = fetch_latest_message()
    if latest_message:
        url = latest_message.strip()
        if url.startswith("http://") or url.startswith("https://"):
            features = extract_features(url)
            user_df = pd.DataFrame([features])
            user_df = user_df[X.columns]
            user_scaled = scaler.transform(user_df)
            prediction = model.predict(user_scaled)
            result = "Go Ahead! "+url+' is not a Phishing Site.' if prediction[0] == 1 else "Stop! "+url+'is a Phishing Site'
            send_message(chat_id, f"{result}\n\nPrediction: {prediction}\n\nResults: \n {features}\n\n")
        else:
            # Check if it's a valid domain name
            if urlparse(url).netloc:
                # Prepend "https://" if missing
                url = "https://" + url
                send_message(chat_id, f"{result}\n\nPrediction: {prediction}\n\nResults: \n {features}\n\n")
            else:
                send_message(chat_id, "Invalid input. Please provide a valid URL or domain name.")

if __name__ == "__main__":
    main()
