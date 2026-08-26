import importlib
import unittest

import pandas as pd

from api.app import extract_url_features


class ApiPredictionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api = importlib.import_module("api.app")
        cls.client = cls.api.app.test_client()

    def build_features(self, overrides):
        features = [0] * 48
        for index, value in overrides.items():
            features[index] = value
        return features

    def test_returns_legitimate_for_benign_features(self):
        features = self.build_features(
            {
                3: 50,
                4: 0,
                6: 0,
                8: 0,
                9: 0,
                14: 0,
                20: 20,
                21: 25,
                22: 0,
            }
        )

        response = self.client.post("/predict", json={"features": features})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["prediction"], "Legitimate Website")

    def test_returns_phishing_for_suspicious_features(self):
        df = pd.read_csv("dataset/phishing_dataset.csv")
        feature_columns = [c for c in df.columns if c not in ["id", "CLASS_LABEL"]]
        row = df.iloc[0]
        features = [row[column] for column in feature_columns]

        response = self.client.post("/predict", json={"features": features})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["prediction"], "Phishing Website")

    def test_extract_url_features_matches_model_schema(self):
        features = extract_url_features("https://login.paypal.com/account?next=%2Fsecurity#login")

        self.assertEqual(len(features), 48)
        self.assertGreater(features[3], 0)
        self.assertEqual(features[14], 0)
        self.assertEqual(features[12], 1)
        self.assertGreaterEqual(features[13], 0)

    def test_deceptive_host_path_url_is_not_reported_as_legitimate(self):
        url = "https://nobell.it/70ffb52d079109dca5564cce6f317373782/login.SkyPe.com/en/cgi-bin/verif/login/70ffb52d"

        response = self.client.post("/predict", json={"url": url})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["prediction"], "Phishing Website")


if __name__ == "__main__":
    unittest.main()
