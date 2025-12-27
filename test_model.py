# python -m pip install coloredlogs flatbuffers numpy packaging protobuf sympy
# python -m pip install -i https://aiinfra.pkgs.visualstudio.com/PublicPackages/_packaging/ORT-Nightly/pypi/simple/ --pre onnxruntime
import onnxruntime as ort
import numpy as np
import sys

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

def main():
    session = ort.InferenceSession(
            "cve_multilabel_classifier.onnx",
            providers=["CPUExecutionProvider"]
        )

    #text = np.array([["grep is vulnerable to DoS attack due to an unsanitized input parameter that can lead to unlimited memory consumption."]])
    text = np.array([[sys.argv[1]]])

    output_name = session.get_outputs()[0].name
    input_name = session.get_inputs()[0].name
    outputs = session.run(
        [output_name],
        {input_name: text}
    )[0][0]

    labels = [
        label
        for label, prob in zip(LABELS, outputs)
        if prob >= THRESHOLDS[label]
    ]

    print(labels if labels else ["other"])

if __name__ == "__main__":
    main()

