class RiskEngine:

    WEIGHTS = {
        "CRITICAL": 40,
        "HIGH": 25,
        "MEDIUM": 10,
        "LOW": 5,
    }

    @classmethod
    def calculate(cls, findings):
        score = sum(cls.WEIGHTS.get(f.get("severity","LOW"),0) for f in findings)
        score = min(score, 100)

        if score >= 80:
            level = "HIGH"
        elif score >= 40:
            level = "MEDIUM"
        elif score > 0:
            level = "LOW"
        else:
            level = "UNKNOWN"

        return score, level
