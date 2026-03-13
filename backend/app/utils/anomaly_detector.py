import numpy as np
from pyod.models.iforest import IForest


class AnomalyDetector:
    """
    Detect anomalous URLs using Isolation Forest.
    """

    def __init__(self):

        self.model = IForest(contamination=0.1)

        # Dummy training data (for MVP)
        X_train = np.array([
            [30, 0, 0, 5],
            [25, 0, 0, 4],
            [40, 0, 0, 6],
            [35, 0, 0, 5],
            [28, 0, 0, 4]
        ])

        self.model.fit(X_train)

    def predict(self, features: dict):

        X = np.array([[
            features["url_length"],
            int(features["has_ip"]),
            features["num_subdomains"],
            features["path_length"]
        ]])

        prediction = self.model.predict(X)

        return bool(prediction[0])