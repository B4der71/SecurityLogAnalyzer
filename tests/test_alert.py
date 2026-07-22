from datetime import datetime

from alerts.alert import Alert


def test_create_alert():

    alert = Alert(
        sid=2001,
        title="Possible Brute Force",
        severity="critical",
        source="windows",
        timestamp=datetime.now(),
        log={}
    )

    assert alert.sid == 2001
    assert alert.title == "Possible Brute Force"
    assert alert.severity == "critical"
    assert alert.source == "windows"