class AlertManager:
    """
    Manages the lifecycle of runtime alerts.
    """

    def __init__(self):
        self.alerts = []

        # Active alerts indexed by fingerprint
        self._active_alerts = {}

    def _fingerprint(self, alert):
        """
        Returns a unique identifier for an alert.
        """

        return (
            alert.sid,
            alert.source,
            alert.log.get("username"),
            alert.log.get("source_ip"),
        )

    def add(self, alert):

        fingerprint = self._fingerprint(alert)

        # Existing alert
        if fingerprint in self._active_alerts:
            existing = self._active_alerts[fingerprint]

            existing.occurrences += 1
            existing.last_seen = alert.timestamp

            return existing

        # New alert
        self.alerts.append(alert)
        self._active_alerts[fingerprint] = alert

        return alert

    def get_alerts(self):
        return self.alerts