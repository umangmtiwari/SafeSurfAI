import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib

# Load the Data
df = pd.read_csv('phishing.csv')

# Preprocess the Data
if 'Index' in df.columns:
    df = df.drop(columns=['Index'])

X = df.drop(columns=['class'])
y = df['class']

# Standardize the feature data
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Split the Data
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.3, random_state=42)

# Train the Model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Save the model and scaler for later use
joblib.dump(model, 'phishing_model.pkl')
joblib.dump(scaler, 'scaler.pkl')

# Load the model and scaler
model = joblib.load('phishing_model.pkl')
scaler = joblib.load('scaler.pkl')

def predict_phishing(features):
    user_df = pd.DataFrame([features])
    user_df = user_df[X.columns]
    user_scaled = scaler.transform(user_df)
    prediction = model.predict(user_scaled)
    return 'Phishing' if prediction[0] == 1 else 'Not Phishing'
