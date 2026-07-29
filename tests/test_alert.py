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
        timestamp=datetime.now(UTC),
        log={}
    )

    assert alert.sid == 2001
    assert alert.title == "Possible Brute Force"
    assert alert.severity == "critical"
    assert alert.source == "windows"

from datetime import datetime

from alerts.alert import Alert


def test_alert_initializes_aggregation_fields():

    timestamp = datetime.now(UTC)

    alert = Alert(
        sid=1001,
        title="Failed Login",
        description="Failed Login",
        severity="high",
        source="windows",
        detection_method="rule",
        timestamp=timestamp,
        log={},
    )

    assert alert.occurrences == 1
    assert alert.status == "active"
    assert alert.first_seen == timestamp
    assert alert.last_seen == timestamp




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
        timestamp=datetime.now(UTC),
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
        timestamp=datetime.now(UTC),
        log={}
    )

    alert2 = Alert(
        sid=2001,
        title="Possible Brute Force",
        description="Test alert",
        severity="critical",
        source="windows",
        detection_method="rule",
        timestamp=datetime.now(UTC),
        log={}
    )

    manager.add(alert1)
    manager.add(alert2)

    alerts = manager.get_alerts()

    assert len(alerts) == 1
    assert alerts[0] == alert1

def test_duplicate_alerts_are_not_added_twice():

    manager = AlertManager()

    alert = Alert(
        sid=1001,
        title="Failed Login",
        description="Failed Login",
        severity="high",
        source="windows",
        detection_method="rule",
        timestamp=datetime.now(UTC),
        log={
            "username": "admin",
            "source_ip": "192.168.1.10",
        },
    )

    manager.add(alert)
    manager.add(alert)

    alerts = manager.get_alerts()

    assert len(alerts) == 1


def test_different_users_create_different_alerts():

    manager = AlertManager()

    alert1 = Alert(
        sid=1001,
        title="Failed Login",
        description="Failed Login",
        severity="high",
        source="windows",
        detection_method="rule",
        timestamp=datetime.now(UTC),
        log={
            "username": "admin",
            "source_ip": "192.168.1.10",
        },
    )

    alert2 = Alert(
        sid=1001,
        title="Failed Login",
        description="Failed Login",
        severity="high",
        source="windows",
        detection_method="rule",
        timestamp=datetime.now(UTC),
        log={
            "username": "john",
            "source_ip": "192.168.1.10",
        },
    )

    manager.add(alert1)
    manager.add(alert2)

    assert len(manager.get_alerts()) == 2


from datetime import datetime, timedelta, UTC


def test_duplicate_alert_updates_occurrences_and_last_seen():

    manager = AlertManager()

    first_time = datetime.now(UTC)
    second_time = first_time + timedelta(seconds=10)

    alert1 = Alert(
        sid=1001,
        title="Failed Login",
        description="Failed Login",
        severity="high",
        source="windows",
        detection_method="rule",
        timestamp=first_time,
        log={
            "username": "admin",
            "source_ip": "192.168.1.10",
        },
    )

    alert2 = Alert(
        sid=1001,
        title="Failed Login",
        description="Failed Login",
        severity="high",
        source="windows",
        detection_method="rule",
        timestamp=second_time,
        log={
            "username": "admin",
            "source_ip": "192.168.1.10",
        },
    )

    manager.add(alert1)
    manager.add(alert2)

    alerts = manager.get_alerts()

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert.occurrences == 2
    assert alert.first_seen == first_time
    assert alert.last_seen == second_time











# ==========================
# Notifier
# ==========================
























































