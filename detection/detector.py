from detection.rule_engine import RuleEngine
from alerts.alert_manager import AlertManager
from alerts.alert import Alert

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

        # Correlation history
        self._history = []

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

        # Save the newly generated alerts
        for alert in detections:
            self._history.append(alert)

        # Keep only the latest 100 alerts
        self._history = self._history[-100:]

        correlation_alerts = []

        correlation_alerts.extend(
            self._detect_bruteforce_success()
        )

        return correlation_alerts

    def _detect_bruteforce_success(self):
        """
        Detect multiple failed logins followed by
        a successful login.

        Returns:
            List[Alert]
        """

        correlation_alerts = []

        # Need at least:
        # Failed
        # Failed
        # Failed
        # Success
        if len(self._history) < 4:
            return correlation_alerts

        latest = self._history[-1]

        # Correlation only starts when the latest alert
        # is a successful login.
        if latest.log.get("event_id") != 4624:
            return correlation_alerts

        username = latest.log.get("username")
        source_ip = latest.log.get("source_ip")

        failed_count = 0

        # Walk backwards through history
        for previous in reversed(self._history[:-1]):

            # Stop if we reach another successful login
            if previous.log.get("event_id") == 4624:
                break

            # Ignore anything except failed logins
            if previous.log.get("event_id") != 4625:
                continue

            # Must be same username
            if previous.log.get("username") != username:
                continue

            # Must be same source IP
            if previous.log.get("source_ip") != source_ip:
                continue

            failed_count += 1

        # Don't generate the same correlation twice
        for previous in reversed(self._history):

            if previous.detection_method != "correlation":
                continue

            if previous.sid == 9001:
                return correlation_alerts

            break

        if failed_count >= 3:

            correlation_alerts.append(
                Alert(
                    sid=9001,
                    title="Brute Force Success",
                    description=(
                        f"{failed_count} failed login attempts "
                        "followed by a successful login."
                    ),
                    severity="critical",
                    source=latest.source,
                    detection_method="correlation",
                    timestamp=latest.timestamp,
                    log=latest.log,
                )
            )

        for alert in correlation_alerts:
            self._history.append(alert)

        self._history = self._history[-100:]

        return correlation_alerts