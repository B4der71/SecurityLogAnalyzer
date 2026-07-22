from detection.rule_engine import RuleEngine


class Detector:
    """
    Main detection coordinator.
    """

    def __init__(self, rules):
        self.rule_engine = RuleEngine(rules)

    def detect(self, log):
        """
        Run all detection engines.

        Returns:
            List of detections.
        """
        detections = []

        detections.extend(
            self.rule_engine.detect(log)
        )

        return detections