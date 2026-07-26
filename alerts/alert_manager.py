class AlertManager:
    """
    Manages the lifecycle of runtime alerts.
    """

    def __init__(self):
        self.alerts = []

    def add(self, alert):
        self.alerts.append(alert)

    def get_alerts(self):
        return self.alerts