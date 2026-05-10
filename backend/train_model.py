import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score, classification_report
import joblib

print("1. Loading dataset...")
# Make sure your CSV has columns named 'text' and 'label'
df = pd.read_csv('emails.csv') 

# Clean up any missing data
df.dropna(inplace=True)

print("2. Converting text to mathematics (TF-IDF)...")
# This converts words into numbers based on how important they are
vectorizer = TfidfVectorizer(stop_words='english', max_features=5000)
X = vectorizer.fit_transform(df['text'])
y = df['label']

print("3. Splitting data into training and testing sets...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print("4. Training the Custom NLP Model...")
model = MultinomialNB() # Naive Bayes is excellent and fast for text classification
model.fit(X_train, y_train)

print("5. Evaluating Accuracy...")
predictions = model.predict(X_test)
print(f"Accuracy: {accuracy_score(y_test, predictions) * 100:.2f}%")
print("\nClassification Report:\n", classification_report(y_test, predictions))

print("6. Saving the model to disk...")
# Save the model and the vectorizer so Flask can use them
joblib.dump(model, 'phishing_model.pkl')
joblib.dump(vectorizer, 'vectorizer.pkl')
print("Done! Custom NLP Engine created.")