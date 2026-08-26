import unittest

from explanation_service import generate_explanation


def build_features(overrides):
    features = [0] * 48
    for index, value in overrides.items():
        features[index] = value
    return features


class ExplanationTests(unittest.TestCase):
    def test_phishing_explanation_mentions_suspicious_indicators(self):
        features = build_features(
            {
                3: 120,
                4: 3,
                6: 1,
                8: 2,
                9: 2,
                14: 1,
                20: 60,
                21: 90,
                22: 80,
            }
        )

        explanation = generate_explanation(features, "Phishing Website")

        self.assertIn("suspicious", explanation.lower())
        self.assertIn("https", explanation.lower())

    def test_legitimate_explanation_mentions_safe_structure(self):
        features = build_features(
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

        explanation = generate_explanation(features, "Legitimate Website")

        self.assertIn("legitimate", explanation.lower())
        self.assertIn("https", explanation.lower())


if __name__ == "__main__":
    unittest.main()
