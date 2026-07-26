class AlertService:

    VALID_SEVERITIES = {
                "low",
                "medium",
                "high",
                "critical"
            }

    VALID_STATUSES = {
            "open",
            "investigating",
            "resolved",
            "closed",
        }


    VALID_TRANSITIONS = {
            "open": {"investigating"},
            "investigating": {"resolved"},
            "resolved": {"closed"},
            "closed": set(),
        }

    def __init__(self, repository):
        self.repository = repository

    def create_alert(self, alert):

        if alert.severity not in self.VALID_SEVERITIES:
            raise ValueError("Invalid severity")

        

        return self.repository.save(alert)

    def get_alert(self, alert_id):
        return self.repository.get_by_id(alert_id)

    def get_open_alerts(self):
        return self.repository.get_open()
    
    def get_alerts_by_severity(self, severity):
        return self.repository.get_by_severity(severity)

    
    def update_status(self, alert_id, status):
        alert = self.repository.get_by_id(alert_id)

        if status not in self.VALID_STATUSES:
            raise ValueError("Invalid status")

        current_status = alert.status

        if status not in self.VALID_TRANSITIONS[current_status]:
            raise ValueError("Invalid status transition")

        return self.repository.update_status(alert_id, status)
        
    def resolve_alert(self, alert_id, resolved_by):
            return self.repository.resolve_alert(alert_id, resolved_by)

    def delete_alert(self, alert_id):
        return self.repository.delete(alert_id)