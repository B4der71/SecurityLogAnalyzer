from detection.rule_engine import RuleEngine
from alerts.alert_manager import AlertManager

class Detector:
    """
    Main detection coordinator.
    """

    def __init__(self, rules):
        self.rule_engine = RuleEngine(rules)
        self.alert_manager = AlertManager()

        # Registered detection engines
        self.detectors = [
            self.rule_engine
        ]

    def detect(self, log):
        """
        Run all detection engines and correlations.

        Returns:
            List[Alert]: Alerts generated for the given log.
        """
        alerts = []

        for detector in self.detectors:
            alerts.extend(detector.detect(log))

        alerts.extend(
            self._run_correlations(log, alerts)
        )

        for alert in alerts:
            self.alert_manager.add(alert)

        return alerts

    def _run_correlations(self, log, detections):
        """
        Evaluate correlation rules.

        Returns:
            List of correlation alerts.
        """
        return []