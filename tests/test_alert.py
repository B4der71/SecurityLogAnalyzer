from datetime import datetime

from alerts.alert import Alert

# ==========================
# Alert
# ==========================

def test_create_alert():

    alert = Alert(
        sid=2001,
        title="Possible Brute Force",
        description="Test alert",
        severity="critical",
        source="windows",
        detection_method="rule",
        timestamp=datetime.now(),
        log={}
    )

    assert alert.sid == 2001
    assert alert.title == "Possible Brute Force"
    assert alert.severity == "critical"
    assert alert.source == "windows"




# ==========================
# AlertManager
# ==========================

from alerts.alert_manager import AlertManager


def test_alert_manager_creation():

    manager = AlertManager()

    assert manager.alerts == []

from datetime import datetime

from alerts.alert import Alert



def test_add_alert():

    manager = AlertManager()

    alert = Alert(
        sid=2001,
        title="Possible Brute Force",
        description="Test alert",
        severity="critical",
        source="windows",
        detection_method="rule",
        timestamp=datetime.now(),
        log={}
    )

    manager.add(alert)

    assert len(manager.alerts) == 1


def test_get_alerts():

    manager = AlertManager()

    alert1 = Alert(
        sid=2001,
        title="Possible Brute Force",
        description="Test alert",
        severity="critical",
        source="windows",
        detection_method="rule",
        timestamp=datetime.now(),
        log={}
    )

    alert2 = Alert(
        sid=2001,
        title="Possible Brute Force",
        description="Test alert",
        severity="critical",
        source="windows",
        detection_method="rule",
        timestamp=datetime.now(),
        log={}
    )

    manager.add(alert1)
    manager.add(alert2)

    alerts = manager.get_alerts()

    assert len(alerts) == 2
    assert alerts[0] == alert1
    assert alerts[1] == alert2














# ==========================
# Notifier
# ==========================
























































