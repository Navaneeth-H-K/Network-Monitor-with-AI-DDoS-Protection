import joblib
import pandas as pd
from config import MODEL_PATH, BLOCK_THRESHOLD


class DetectionEngine:

    def __init__(self):
        self.model = joblib.load(MODEL_PATH)

    def predict(self, features):

        df = pd.DataFrame([[
            features["syn_count"],
            features["ack_count"],
            features["packet_rate"],
            features["syn_ack_ratio"],
            features["avg_frame_len"]
        ]], columns=[
            "syn_count",
            "ack_count",
            "packet_rate",
            "syn_ack_ratio",
            "avg_frame_len"
        ])

        prediction = self.model.predict(df)[0]

        if prediction == BLOCK_THRESHOLD:
            return "ATTACK"
        else:
            return "NORMAL"
