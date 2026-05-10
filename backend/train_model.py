from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import ComplementNB


BASE_DIR = Path(__file__).resolve().parent
DATASET_DIR = BASE_DIR / "datasets"
MODEL_PATH = BASE_DIR / "phishing_model.pkl"
VECTORIZER_PATH = BASE_DIR / "vectorizer.pkl"

DATASET_FILES = [
    "emails.csv",
    "phishing_email.csv",
    "CEAS_08.csv",
    "Enron.csv",
    "Ling.csv",
    "Nazario.csv",
    "Nigerian_Fraud.csv",
    "SpamAssasin.csv",
]

TEXT_COLUMN_CANDIDATES = [
    "text",
    "text_combined",
    "email",
    "message",
    "content",
]

LABEL_MAP = {
    "0": 0,
    "ham": 0,
    "legitimate": 0,
    "safe": 0,
    "not phishing": 0,
    "non-phishing": 0,
    "1": 1,
    "phish": 1,
    "phishing": 1,
    "spam": 1,
    "scam": 1,
    "malicious": 1,
}


def normalize_label(value):
    key = str(value).strip().lower()
    if key in LABEL_MAP:
        return LABEL_MAP[key]
    return None


def combine_text_columns(df):
    lower_to_original = {column.lower(): column for column in df.columns}

    for candidate in TEXT_COLUMN_CANDIDATES:
        if candidate in lower_to_original:
            return df[lower_to_original[candidate]].fillna("").astype(str)

    parts = []
    for candidate in ("subject", "body", "urls"):
        if candidate in lower_to_original:
            parts.append(df[lower_to_original[candidate]].fillna("").astype(str))

    if not parts:
        raise ValueError("No supported text columns found")

    combined = parts[0]
    for part in parts[1:]:
        combined = combined + " " + part
    return combined


def load_dataset(path):
    df = pd.read_csv(path, low_memory=False)
    lower_to_original = {column.lower(): column for column in df.columns}

    if "label" not in lower_to_original:
        raise ValueError("Missing label column")

    labels = df[lower_to_original["label"]].map(normalize_label)
    text = combine_text_columns(df)

    normalized = pd.DataFrame({"label": labels, "text": text})
    normalized["text"] = (
        normalized["text"]
        .str.replace(r"\s+", " ", regex=True)
        .str.strip()
    )
    normalized = normalized.dropna(subset=["label"])
    normalized = normalized[normalized["text"].str.len() >= 20]
    normalized["label"] = normalized["label"].astype(int)

    return normalized


def load_all_datasets():
    frames = []

    for filename in DATASET_FILES:
        path = DATASET_DIR / filename
        if not path.exists():
            print(f"Skipping missing dataset: {path.name}")
            continue

        print(f"Loading {path.name}...")
        try:
            frame = load_dataset(path)
        except Exception as exc:
            print(f"  Skipped {path.name}: {exc}")
            continue

        counts = frame["label"].value_counts().sort_index().to_dict()
        print(f"  Loaded {len(frame):,} usable rows: {counts}")
        frames.append(frame)

    if not frames:
        raise RuntimeError(f"No usable CSV datasets found in {DATASET_DIR}")

    combined = pd.concat(frames, ignore_index=True)
    before_dedupe = len(combined)
    combined = combined.drop_duplicates(subset=["text"]).sample(frac=1, random_state=42)
    print(f"Removed {before_dedupe - len(combined):,} duplicate rows.")

    return combined


def main():
    print("1. Loading and normalizing datasets...")
    df = load_all_datasets()
    print("Final class distribution:")
    print(df["label"].value_counts().sort_index().rename(index={0: "legitimate", 1: "phishing/spam"}))

    print("\n2. Converting text to TF-IDF features...")
    vectorizer = TfidfVectorizer(
        stop_words="english",
        lowercase=True,
        ngram_range=(1, 2),
        min_df=2,
        max_df=0.95,
        max_features=120000,
        sublinear_tf=True,
    )
    X = vectorizer.fit_transform(df["text"])
    y = df["label"]

    print("3. Splitting data into training and testing sets...")
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    print("4. Training phishing classifier...")
    model = ComplementNB(alpha=0.2)
    model.fit(X_train, y_train)

    print("5. Evaluating model...")
    predictions = model.predict(X_test)
    print(f"Accuracy: {accuracy_score(y_test, predictions) * 100:.2f}%")
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, predictions, labels=[0, 1]))
    print("\nClassification Report:")
    print(classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["legitimate", "phishing/spam"],
    ))

    print("6. Saving model artifacts...")
    joblib.dump(model, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)
    print(f"Saved model to {MODEL_PATH}")
    print(f"Saved vectorizer to {VECTORIZER_PATH}")


if __name__ == "__main__":
    main()
