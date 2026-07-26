from database.models import Alert as AlertModel
from datetime import datetime

class AlertRepository:

    def __init__(self, session):
        self.session = session

    def save(self, alert):
        db_alert = AlertModel(
            log_id=alert.log.log_id,
            sid=alert.sid,
            title=alert.title,
            description=alert.description,
            severity=alert.severity,
            source=alert.source,
            detection_method=alert.detection_method,
            ml_model=alert.ml_model,
            ml_confidence=alert.ml_confidence,
        )

        self.session.add(db_alert)
        self.session.commit()

        return db_alert

    def get_by_id(self, alert_id):
        return (
            self.session.query(AlertModel)
            .filter_by(alert_id=alert_id)
            .first()
        )

    def get_all(self):
        return self.session.query(AlertModel).all()

    def get_open(self):
        return (
            self.session.query(AlertModel)
            .filter_by(status="open")
            .all()
        )

    def get_by_severity(self, severity):
        return (
            self.session.query(AlertModel)
            .filter_by(severity=severity)
            .all()
        )

    def update_status(self, alert_id, status):
        alert = (
            self.session.query(AlertModel)
            .filter_by(alert_id=alert_id)
            .first()
        )

        if alert is None:
            return None

        alert.status = status
        self.session.commit()

        return alert

    def resolve_alert(self, alert_id, resolved_by):
        alert = (
            self.session.query(AlertModel)
            .filter_by(alert_id=alert_id)
            .first()
        )

        if alert is None:
            return None

        alert.status = "closed"
        alert.resolved_by = resolved_by
        alert.resolved_at = datetime.utcnow()

        self.session.commit()

        return alert


    def delete(self, alert_id):
        alert = (
            self.session.query(AlertModel)
            .filter_by(alert_id=alert_id)
            .first()
        )

        if alert is None:
            return False

        self.session.delete(alert)
        self.session.commit()

        return True















    