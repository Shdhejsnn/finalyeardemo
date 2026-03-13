from __future__ import annotations

import argparse
import logging
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


LOGGER = logging.getLogger(__name__)
DEFAULT_OUTPUT = Path(__file__).resolve().parents[2] / "models" / "phishing_model.pkl"


def build_pipeline() -> Pipeline:
    """
    Character n-grams capture phishing URL patterns far better than
    a small hand-engineered feature set on this dataset.
    """
    return Pipeline(
        steps=[
            (
                "tfidf",
                TfidfVectorizer(
                    analyzer="char",
                    ngram_range=(3, 5),
                    min_df=2,
                    max_features=150000,
                    lowercase=True,
                    sublinear_tf=True,
                ),
            ),
            (
                "classifier",
                LogisticRegression(
                    max_iter=1000,
                    class_weight="balanced",
                    solver="liblinear",
                    random_state=42,
                ),
            ),
        ]
    )


def train_model(dataset_path: str | Path, output_path: str | Path = DEFAULT_OUTPUT) -> Path:
    data_path = Path(dataset_path)
    if not data_path.exists():
        raise FileNotFoundError(f"Dataset not found: {data_path}")

    LOGGER.info("Loading dataset from %s", data_path)
    data_frame = pd.read_csv(data_path)
    _validate_columns(data_frame)

    data_frame = data_frame.dropna(subset=["URL", "Label"]).copy()
    data_frame["Label"] = data_frame["Label"].astype(str).str.strip().str.lower()
    data_frame["Label"] = data_frame["Label"].map({"bad": 1, "good": 0})
    data_frame = data_frame.dropna(subset=["Label"])
    data_frame["Label"] = data_frame["Label"].astype(int)

    x_train, x_test, y_train, y_test = train_test_split(
        data_frame["URL"],
        data_frame["Label"],
        test_size=0.2,
        random_state=42,
        stratify=data_frame["Label"],
    )

    model = build_pipeline()
    LOGGER.info("Training phishing model on %s rows", len(x_train))
    model.fit(x_train, y_train)

    predictions = model.predict(x_test)
    accuracy = accuracy_score(y_test, predictions)
    LOGGER.info("Model accuracy: %.4f", accuracy)
    LOGGER.info("Classification report:\n%s", classification_report(y_test, predictions))

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, output)
    LOGGER.info("Saved phishing model to %s", output)
    return output


def _validate_columns(data_frame: pd.DataFrame) -> None:
    required_columns = {"URL", "Label"}
    missing_columns = required_columns.difference(data_frame.columns)
    if missing_columns:
        raise ValueError(f"Dataset missing required columns: {sorted(missing_columns)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the ShieldX phishing URL model.")
    parser.add_argument(
        "dataset_path",
        nargs="?",
        default="data/phishing_site_urls.csv",
        help="Path to the phishing dataset CSV.",
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        help="Where to save the trained model.",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
    train_model(args.dataset_path, args.output)


if __name__ == "__main__":
    main()
