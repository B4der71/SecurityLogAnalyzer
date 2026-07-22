from detection.rule_engine import RuleEngine


class Detector:
    """
    Main detection coordinator.
    """

    def __init__(self, rules):
        self.rule_engine = RuleEngine(rules)

        # Registered detection engines
        self.detectors = [
            self.rule_engine
        ]

    def detect(self, log):
        """
        Run all detection engines.

        Returns:
            List of detections.
        """
        detections = []

        for detector in self.detectors:
            detections.extend(
                detector.detect(log)
            )

        detections.extend(
            self._run_correlations(log, detections)
        )

        return detections

    def _run_correlations(self, log, detections):
        """
        Evaluate correlation rules.

        Returns:
            List of correlation alerts.
        """
        return []