import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
import joblib

# Load and preprocess
df = pd.read_csv('phishing.csv')
if 'Index' in df.columns:
    df = df.drop(columns=['Index'])
X = df.drop(columns=['class'])
y = df['class']

# Scale and split
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.3, random_state=42)

# Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Save model and scaler
joblib.dump(model, 'model/phishing_model.pkl')
joblib.dump(scaler, 'model/scaler.pkl')
