import pandas as pd
import numpy as np
import onnxruntime as rt

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB  # Changed import
from sklearn.multioutput import MultiOutputClassifier
from sklearn.metrics import confusion_matrix, classification_report
from sklearn.pipeline import Pipeline

# ONNX Import tools
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import StringTensorType

# ==========================================
# 1. Load and Prepare Data
# ==========================================
try:
    df = pd.read_csv('cve_multilabel_dataset.csv')
    print("Dataset loaded successfully.")
except FileNotFoundError:
    print("Error: 'cve_multilabel_dataset.csv' not found. Please verify the file path.")
    exit()

X = df['description']
label_columns = [
    'arbitrary_file_write',
    'system_privileges_escalation',
    'resource_exhaustion',
    'code_execution',
    'arbitrary_file_read',
    'application_privileges_escalation'
]
y = df[label_columns]

# Split into train/test (80/20)
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# ==========================================
# 2. Build and Train Pipeline (Multinomial)
# ==========================================
pipeline = Pipeline([
    # binary=False allows the model to count word frequencies, not just presence
    ('vectorizer', CountVectorizer(stop_words='english', binary=False)),
    ('classifier', MultiOutputClassifier(MultinomialNB()))
])

print("Training Multinomial model...")
pipeline.fit(X_train, y_train)
print("Training complete.")

# ==========================================
# 3. Evaluate Model (Confusion Matrix)
# ==========================================
print("\n--- Evaluation Results ---")
y_pred = pipeline.predict(X_test)

for i, col in enumerate(label_columns):
    print(f"\n### Label: {col} ###")
    y_true_col = y_test.iloc[:, i]
    y_pred_col = y_pred[:, i]

    cm = confusion_matrix(y_true_col, y_pred_col)
    print(f"Confusion Matrix:\n{cm}")
    # We use zero_division=0 to avoid warnings if a label never appears in the test set
    print(classification_report(y_true_col, y_pred_col, zero_division=0))

# ==========================================
# 4. Export to ONNX
# ==========================================
print("\n--- Exporting to ONNX ---")

# Define input type: A tensor of strings (N rows, 1 column)
initial_type = [('description_input', StringTensorType([None, 1]))]

# Convert the pipeline
onnx_model = convert_sklearn(
    pipeline,
    initial_types=initial_type,
    target_opset=12,
    name="CVE_MultinomialNB_Classifier"
)

# Save to file
onnx_filename = "vex8s_cve_classifier.onnx"
with open(onnx_filename, "wb") as f:
    f.write(onnx_model.SerializeToString())

print(f"✅ Model successfully exported to '{onnx_filename}'")

# ==========================================
# 5. Verify ONNX Model (Inference Test)
# ==========================================
print("\n--- Verifying ONNX Inference ---")

sess = rt.InferenceSession(onnx_filename, providers=["CPUExecutionProvider"])
input_name = sess.get_inputs()[0].name

# Test with a dummy CVE description
test_text = "Heap-based buffer overflow in the image processor allows code execution."
input_data = np.array([[test_text]])

pred_onx = sess.run(None, {input_name: input_data})

print(f"Test Description: '{test_text}'")
print(f"Predicted Labels (Order: {label_columns}):")
print(pred_onx[0])
