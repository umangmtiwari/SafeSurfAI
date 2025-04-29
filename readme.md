# 🛡️ SafeSurfAI - Phishing URL Detection

SafeSurfAI is an intelligent web application designed to detect **phishing websites** using **machine learning** and advanced **feature engineering**. It automates URL inspection by analyzing its structure, behavior, and metadata to predict whether the website is malicious or safe.


### 🚀 Live App

👉 [Launch SafeSurfAI](https://safesurfai.onrender.com/)

## 🧠 Machine Learning Overview

SafeSurfAI uses a supervised classification model trained on a labeled dataset of phishing and legitimate URLs. The model learns patterns from over **30 handcrafted features**, many of which are extracted dynamically using live URL analysis.

### ✅ Model Summary:

- **Model Type**: Random Forest Classifier (or equivalent)
- **Accuracy**: ~96% on validation data
- **Training Dataset**: Phishing dataset with ~11,000 entries
- **Evaluation Metrics**: Accuracy, Precision, Recall, F1-score


## 🧪 Feature Engineering

Features are divided into **5 key categories**, extracted both statically and dynamically from the URL and its web page.

### 1. **Address Bar-Based Features**
| Feature | Description |
|--------|-------------|
| `Having_IP_Address` | Checks if IP is used instead of domain |
| `URL_Length` | Long URLs often indicate phishing |
| `@_Symbol` | Presence of `@` symbol in the URL |
| `Prefix/Suffix` | Hyphens in domain names (e.g., `secure-bank.com`) |
| `HTTPS_Token` | Checks if HTTPS is included in domain as deception |

### 2. **Abnormal Domain Features**
| Feature | Description |
|--------|-------------|
| `DNS_Record` | Absence indicates phishing |
| `Web_Traffic` | Alexa Rank or Google index status |
| `Domain_Age` | New domains are riskier |
| `Domain_Registration_Length` | Short registration is suspicious |

### 3. **HTML & JavaScript Features**
| Feature | Description |
|--------|-------------|
| `Using_iFrame` | Phishing often uses hidden frames |
| `OnMouseOver` | Mouse-over redirection to fake links |
| `RightClick_Disabled` | Prevents user inspection |
| `Popup_Window` | Suspicious behavior to gather data |

### 4. **Content-Based Features**
| Feature | Description |
|--------|-------------|
| `Anchor_Tags` | % of external vs internal links |
| `Favicon` | Loaded from external source? |
| `Request_URL` | Loads resources from different domain? |
| `Script_Source` | External JS usage ratio |

### 5. **Search Engine & Registry Features**
| Feature | Description |
|--------|-------------|
| `Google_Index` | Is the site indexed by Google? |
| `Page_Rank` | High-ranking sites are more trusted |
| `WHOIS_Status` | Checks WHOIS availability and details |

---

## 🧬 ML Pipeline

```python
pipeline = Pipeline([
    ('scaling', StandardScaler()),
    ('classifier', RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42))
])
```

- **Scaler**: StandardScaler ensures all features contribute equally
- **Model**: Random Forest chosen for interpretability and robustness to outliers
- **Model Persistence**: Saved using `joblib` for fast loading in the Flask app


## 🧰 Technologies Used

- **Backend**: Python, Flask
- **ML/DS Libraries**: scikit-learn, pandas, numpy
- **Web Scraping**: BeautifulSoup, requests
- **WHOIS/DNS Tools**: python-whois, socket
- **Frontend**: HTML, CSS, Bootstrap (Jinja2 templates)


## 📦 Project Structure

```bash
phishing-url-detector/
│
├── model/
│   ├── phishing_model.pkl
│   └── scaler.pkl
│
├── templates/
│   └── index.html
│
├── phishing.csv
├── app.py
├── README.md
└── requirements.txt
```


## 🚀 Local Setup Instructions

```bash
git clone https://github.com/your-username/safesurfai.git
cd safesurfai
python -m venv venv
source venv/bin/activate  # For Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Visit `http://127.0.0.1:5000` in your browser.


## 💡 Possible Enhancements

- ✅ Add deep learning model for raw URL sequence prediction
- 🌍 Add real-time DNS blacklisting APIs (Google Safe Browsing, VirusTotal)
- 🔐 Include certificate validity checks via SSL libraries
- 📱 Build mobile-first frontend or Chrome extension version
- 📊 Add model explainability (SHAP/LIME) for feature importance visualization


## 🔗 Live Deployment

Hosted on **Render**  
🌐 [https://safesurfai.onrender.com/](https://safesurfai.onrender.com/)


## 🙏 Acknowledgments

- Libraries: scikit-learn, Flask, BeautifulSoup, WHOIS
- Cloud: Render.com for free hosting