import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
import joblib

# Load dataset
df = pd.read_csv('dataset.csv')

# Features and labels
X = df['data']
y = df['label']

# Vectorize text
vectorizer = TfidfVectorizer()
X_vect = vectorizer.fit_transform(X)

# Train model
model = MultinomialNB()
model.fit(X_vect, y)

# Save model and vectorizer
joblib.dump(model, 'model.pkl')
joblib.dump(vectorizer, 'vectorizer.pkl')
print("✅ Model trained and saved.")
