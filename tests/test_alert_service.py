from datetime import datetime, UTC
import pytest

from services.alert_service import AlertService
from database.alert_repository import AlertRepository
from database.models import Log
from alerts.alert import Alert


def test_create_alert(db_session):
    # Arrange
    repository = AlertRepository(db_session)
    service = AlertService(repository)

    log = Log(
        timestamp=datetime.now(UTC),
        log_type="windows",
        source="windows.evtx",
        raw_log="Test Log",
    )

    db_session.add(log)
    db_session.commit()

    alert = Alert(
        sid=1001,
        title="Test Alert",
        description="Created via service",
        severity="high",
        source="windows",
        detection_method="rule",
        timestamp=datetime.now(UTC),
        log=log,
    )

    # Act
    created = service.create_alert(alert)

    # Assert
    assert created is not None
    assert created.alert_id is not None
    assert created.title == "Test Alert"



def test_get_alert(db_session):
    # Arrange
    repository = AlertRepository(db_session)
    service = AlertService(repository)

    log = Log(
        timestamp=datetime.now(UTC),
        log_type="windows",
        source="windows.evtx",
        raw_log="Test Log",
    )

    db_session.add(log)
    db_session.commit()

    alert = Alert(
        sid=1001,
        title="Retrieve Alert",
        description="Retrieve via service",
        severity="high",
        source="windows",
        detection_method="rule",
        timestamp=datetime.now(UTC),
        log=log,
    )

    created = service.create_alert(alert)

    # Act
    retrieved = service.get_alert(created.alert_id)

    # Assert
    assert retrieved is not None
    assert retrieved.alert_id == created.alert_id
    assert retrieved.title == "Retrieve Alert"


def test_get_open_alerts(db_session):
    # Arrange
    repository = AlertRepository(db_session)
    service = AlertService(repository)

    log = Log(
        timestamp=datetime.now(UTC),
        log_type="windows",
        source="windows.evtx",
        raw_log="Test Log",
    )

    db_session.add(log)
    db_session.commit()

    alert1 = Alert(
        sid=1001,
        title="Open Alert",
        description="Open",
        severity="high",
        source="windows",
        detection_method="rule",
        timestamp=datetime.now(UTC),
        log=log,
    )

    alert2 = Alert(
        sid=1002,
        title="Closed Alert",
        description="Closed",
        severity="medium",
        source="windows",
        detection_method="rule",
        timestamp=datetime.now(UTC),
        log=log,
    )

    open_alert = service.create_alert(alert1)
    closed_alert = service.create_alert(alert2)

    service.resolve_alert(
        closed_alert.alert_id,
        "analyst1"
    )

    # Act
    alerts = service.get_open_alerts()

    # Assert
    assert any(alert.alert_id == open_alert.alert_id for alert in alerts)
    assert all(alert.status == "open" for alert in alerts)

def test_get_alerts_by_severity(db_session):
    # Arrange
    repository = AlertRepository(db_session)
    service = AlertService(repository)

    log = Log(
        timestamp=datetime.now(UTC),
        log_type="windows",
        source="windows.evtx",
        raw_log="Test Log",
    )

    db_session.add(log)
    db_session.commit()

    high_alert = Alert(
        sid=1001,
        title="High Alert",
        description="High severity",
        severity="high",
        source="windows",
        detection_method="rule",
        timestamp=datetime.now(UTC),
        log=log,
    )

    low_alert = Alert(
        sid=1002,
        title="Low Alert",
        description="Low severity",
        severity="low",
        source="windows",
        detection_method="rule",
        timestamp=datetime.now(UTC),
        log=log,
    )

    service.create_alert(high_alert)
    service.create_alert(low_alert)

    # Act
    alerts = service.get_alerts_by_severity("high")

    # Assert
    assert len(alerts) >= 1
    assert all(alert.severity == "high" for alert in alerts)

def test_update_alert_status(db_session):
    # Arrange
    repository = AlertRepository(db_session)
    service = AlertService(repository)

    log = Log(
        timestamp=datetime.now(UTC),
        log_type="windows",
        source="windows.evtx",
        raw_log="Test Log",
    )

    db_session.add(log)
    db_session.commit()

    alert = Alert(
        sid=1001,
        title="Status Test",
        description="Testing status update",
        severity="high",
        source="windows",
        detection_method="rule",
        timestamp=datetime.now(UTC),
        log=log,
    )

    created = service.create_alert(alert)

    # Act
    updated = service.update_status(created.alert_id, "investigating")

    # Assert
    assert updated.status == "investigating"

def test_delete_alert(db_session):
    # Arrange
    repository = AlertRepository(db_session)
    service = AlertService(repository)

    log = Log(
        timestamp=datetime.now(UTC),
        log_type="windows",
        source="windows.evtx",
        raw_log="Test Log",
    )

    db_session.add(log)
    db_session.commit()

    alert = Alert(
        sid=1001,
        title="Delete Test",
        description="Testing delete",
        severity="high",
        source="windows",
        detection_method="rule",
        timestamp=datetime.now(UTC),
        log=log,
    )

    created = service.create_alert(alert)

    # Act
    result = service.delete_alert(created.alert_id)

    # Assert
    assert result is True
    assert service.get_alert(created.alert_id) is None

def test_create_alert_invalid_severity(db_session):
    # Arrange
    repository = AlertRepository(db_session)
    service = AlertService(repository)

    log = Log(
        timestamp=datetime.now(UTC),
        log_type="windows",
        source="windows.evtx",
        raw_log="Test Log",
    )

    db_session.add(log)
    db_session.commit()

    alert = Alert(
        sid=1001,
        title="Invalid Severity",
        description="Should fail",
        severity="super-high",
        source="windows",
        detection_method="rule",
        timestamp=datetime.now(UTC),
        log=log,
    )

    # Act / Assert
    with pytest.raises(ValueError, match="Invalid severity"):
        service.create_alert(alert)

def test_update_alert_invalid_status(db_session):
    repository = AlertRepository(db_session)
    service = AlertService(repository)

    log = Log(
        timestamp=datetime.now(UTC),
        log_type="windows",
        source="windows.evtx",
        raw_log="Test Log",
    )

    db_session.add(log)
    db_session.commit()

    alert = Alert(
        sid=1001,
        title="Status Test",
        description="Testing",
        severity="high",
        source="windows",
        detection_method="rule",
        timestamp=datetime.now(UTC),
        log=log,
    )

    created = service.create_alert(alert)

    with pytest.raises(ValueError, match="Invalid status"):
        service.update_status(created.alert_id, "processing")

def test_invalid_status_transition(db_session):
    repository = AlertRepository(db_session)
    service = AlertService(repository)

    log = Log(
        timestamp=datetime.now(UTC),
        log_type="windows",
        source="windows.evtx",
        raw_log="Test Log",
    )

    db_session.add(log)
    db_session.commit()

    alert = Alert(
        sid=1001,
        title="Transition Test",
        description="Testing transitions",
        severity="high",
        source="windows",
        detection_method="rule",
        timestamp=datetime.now(UTC),
        log=log,
    )

    created = service.create_alert(alert)

    # Move to investigating (valid)
    service.update_status(created.alert_id, "investigating")

    # Move back to open (invalid)
    with pytest.raises(ValueError, match="Invalid status transition"):
        service.update_status(created.alert_id, "open")










































