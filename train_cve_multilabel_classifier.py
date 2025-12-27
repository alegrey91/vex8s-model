#!/usr/bin/env python3

"""
Multi-label CVE classifier:
- TF-IDF (1–2 grams)
- One-vs-Rest Logistic Regression
- Exports to ONNX for production inference
"""

import re
import numpy as np
import pandas as pd

from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.multiclass import OneVsRestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, f1_score, hamming_loss

from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import StringTensorType

import onnxruntime as ort


# =========================
# Configuration
# =========================

DATASET_PATH = "cve_multilabel_dataset.csv"
ONNX_MODEL_PATH = "cve_multilabel_classifier.onnx"

LABELS = [
    "arbitrary_file_write_access",
    "privilege_escalation",
    "resource_exhaustion",
]

THRESHOLDS = {
    "arbitrary_file_write_access": 0.4,
    "privilege_escalation": 0.4,
    "resource_exhaustion": 0.3,
}


# =========================
# Preprocessing
# =========================

def preprocess(text: str) -> str:
    text = text.lower()
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


# =========================
# Load dataset
# =========================

def load_dataset(path: str):
    """
    Expected CSV format:

    id,description,arbitrary_file_write_access,privilege_escalation,resource_exhaustion
    CVE-2023-1111,"Allows attacker to overwrite files",1,0,0
    """
    df = pd.read_csv(path, on_bad_lines='skip')
    print(df.columns)

    df["description"] = df["description"].apply(preprocess)

    X = df["description"]
    y = df[LABELS]

    return X, y


# =========================
# Train model
# =========================

def train_model(X, y):
    pipeline = Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                ngram_range=(1, 2),
                min_df=5,
                max_df=0.9,
                sublinear_tf=True,
            ),
        ),
        (
            "clf",
            OneVsRestClassifier(
                LogisticRegression(
                    max_iter=500,
                    class_weight="balanced",
                )
            ),
        ),
    ])

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
    )

    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)

    print("\n=== Classification report ===")
    print(classification_report(y_test, y_pred, target_names=LABELS))

    print("Micro F1 :", f1_score(y_test, y_pred, average="micro"))
    print("Macro F1 :", f1_score(y_test, y_pred, average="macro"))
    print("Hamming  :", hamming_loss(y_test, y_pred))

    return pipeline


# =========================
# Export to ONNX
# =========================

def export_to_onnx(pipeline, output_path: str):
    onnx_model = convert_sklearn(
        pipeline,
        initial_types=[("input", StringTensorType([None, 1]))],
        options={
            id(pipeline.named_steps["clf"]): {"zipmap": False}
        },
    )

    # Optional metadata
    meta = onnx_model.metadata_props.add()
    meta.key = "labels"
    meta.value = ",".join(LABELS)

    with open(output_path, "wb") as f:
        f.write(onnx_model.SerializeToString())

    print(f"\nONNX model exported to: {output_path}")


# =========================
# ONNX Runtime inference
# =========================

class ONNXPredictor:
    def __init__(self, model_path: str):
        self.session = ort.InferenceSession(
            model_path,
            providers=["CPUExecutionProvider"],
        )
        self.input_name = self.session.get_inputs()[0].name
        self.output_name = self.session.get_outputs()[0].name

    def predict_proba(self, text: str):
        text = preprocess(text)
        probs = self.session.run(
            [self.output_name],
            {self.input_name: np.array([[text]], dtype=object)},
        )[0][0]
        return probs

    def predict_labels(self, text: str):
        probs = self.predict_proba(text)

        labels = [
            label
            for label, prob in zip(LABELS, probs)
            if prob >= THRESHOLDS[label]
        ]

        return labels if labels else ["other"]


# =========================
# Main
# =========================

def main():
    X, y = load_dataset(DATASET_PATH)

    pipeline = train_model(X, y)

    export_to_onnx(pipeline, ONNX_MODEL_PATH)

    # ---- Sanity check with ONNX Runtime ----
    predictor = ONNXPredictor(ONNX_MODEL_PATH)

    sample = (
            "A user can create temporary file on the host filesystem by using a POST request to /hello/{message} in TestWeb 10.2.3."
    )

    print("\n=== Sample inference ===")
    print("Text:", sample)
    print("Probabilities:", predictor.predict_proba(sample))
    print("Labels:", predictor.predict_labels(sample))


if __name__ == "__main__":
    main()

