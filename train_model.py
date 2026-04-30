import joblib
import pandas as pd
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split


def main():
    dataset_path = Path("dataset") / "phishing_dataset.csv"
    model_path = Path("model") / "phishing_model.pkl"

    df = pd.read_csv(dataset_path)
    feature_columns = [c for c in df.columns if c not in ["id", "CLASS_LABEL"]]
    X = df[feature_columns]
    y = df["CLASS_LABEL"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_path)

    accuracy = model.score(X_test, y_test)
    print(f"Saved model to: {model_path}")
    print(f"Test accuracy: {accuracy:.4f}")


if __name__ == "__main__":
    main()
