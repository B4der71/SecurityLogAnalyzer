from datetime import datetime, timedelta, UTC

from alerts.alert import Alert
from database.alert_repository import AlertRepository
from database.models import Alert as AlertModel
from database.models import Log


def test_save_alert(db_session):
    # Arrange
    log = Log(
        timestamp=datetime.now(UTC),
        log_type="windows",
        source="windows.evtx",
        raw_log="4625 Failed Login"
    )

    db_session.add(log)
    db_session.commit()

    alert = Alert(
        sid=1001,
        title="Failed Login",
        description="Multiple failed login attempts detected.",
        severity="high",
        source="windows",
        detection_method="rule",
        timestamp=datetime.now(UTC),
        log=log,
    )

    repository = AlertRepository(db_session)

    # Act
    saved_alert = repository.save(alert)

    # Assert
    saved = (
        db_session.query(AlertModel)
        .filter_by(alert_id=saved_alert.alert_id)
        .first()
    )

    assert saved is not None
    assert saved.sid == 1001
    assert saved.title == "Failed Login"
    assert saved.description == "Multiple failed login attempts detected."
    assert saved.severity == "high"
    assert saved.source == "windows"
    assert saved.detection_method == "rule"
    assert saved.log_id == log.log_id



def test_get_alert_by_id(db_session):
    # Arrange
    log = Log(
        timestamp=datetime.now(UTC),
        log_type="windows",
        source="windows.evtx",
        raw_log="4625 Failed Login"
    )

    db_session.add(log)
    db_session.commit()

    alert = Alert(
        sid=1001,
        title="Failed Login",
        description="Multiple failed login attempts detected.",
        severity="high",
        source="windows",
        detection_method="rule",
        timestamp=datetime.now(UTC),
        log=log,
    )

    repository = AlertRepository(db_session)

    saved_alert = repository.save(alert)

    # Act
    result = repository.get_by_id(saved_alert.alert_id)

    # Assert
    assert result is not None
    assert result.alert_id == saved_alert.alert_id
    assert result.sid == 1001
    assert result.title == "Failed Login"


def test_get_all_alerts(db_session):
        # Arrange
        repository = AlertRepository(db_session)

        log = Log(
            timestamp=datetime.now(UTC),
            log_type="windows",
            source="windows.evtx",
            raw_log="Test Log"
        )

        db_session.add(log)
        db_session.commit()

        alert1 = Alert(
            sid=1001,
            title="Failed Login",
            description="First alert",
            severity="high",
            source="windows",
            detection_method="rule",
            timestamp=datetime.now(UTC),
            log=log,
        )

        alert2 = Alert(
            sid=1002,
            title="PowerShell Execution",
            description="Second alert",
            severity="medium",
            source="windows",
            detection_method="rule",
            timestamp=datetime.now(UTC),
            log=log,
        )

        repository.save(alert1)
        repository.save(alert2)

        # Act
        alerts = repository.get_all()

        # Assert
        assert len(alerts) >= 2
        assert any(alert.sid == 1001 for alert in alerts)
        assert any(alert.sid == 1002 for alert in alerts)

def test_get_open_alerts(db_session):
    # Arrange
    repository = AlertRepository(db_session)

    log = Log(
        timestamp=datetime.now(UTC),
        log_type="windows",
        source="windows.evtx",
        raw_log="Test Log"
    )

    db_session.add(log)
    db_session.commit()

    alert1 = Alert(
        sid=1001,
        title="Open Alert",
        description="Still open",
        severity="high",
        source="windows",
        detection_method="rule",
        timestamp=datetime.now(UTC),
        log=log,
    )

    alert2 = Alert(
        sid=1002,
        title="Closed Alert",
        description="Already resolved",
        severity="medium",
        source="windows",
        detection_method="rule",
        timestamp=datetime.now(UTC),
        log=log,
    )

    open_alert = repository.save(alert1)
    closed_alert = repository.save(alert2)

    # Mark one alert as closed
    closed_alert.status = "closed"
    db_session.commit()

    # Act
    alerts = repository.get_open()

    # Assert
    assert any(alert.alert_id == open_alert.alert_id for alert in alerts)
    assert all(alert.status == "open" for alert in alerts)


def test_get_alerts_by_severity(db_session):
    # Arrange
    repository = AlertRepository(db_session)

    log = Log(
        timestamp=datetime.now(UTC),
        log_type="windows",
        source="windows.evtx",
        raw_log="Test Log"
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

    repository.save(high_alert)
    repository.save(low_alert)

    # Act
    alerts = repository.get_by_severity("high")

    # Assert
    assert len(alerts) >= 1
    assert all(alert.severity == "high" for alert in alerts)


def test_update_alert_status(db_session):
    # Arrange
    repository = AlertRepository(db_session)

    log = Log(
        timestamp=datetime.now(UTC),
        log_type="windows",
        source="windows.evtx",
        raw_log="Test Log"
    )

    db_session.add(log)
    db_session.commit()

    alert = Alert(
        sid=1001,
        title="Test Alert",
        description="Testing status update",
        severity="high",
        source="windows",
        detection_method="rule",
        timestamp=datetime.now(UTC),
        log=log,
    )

    saved_alert = repository.save(alert)

    # Act
    repository.update_status(
        saved_alert.alert_id,
        "in_progress"
    )

    updated = repository.get_by_id(saved_alert.alert_id)

    # Assert
    assert updated.status == "in_progress"


def test_resolve_alert(db_session):
    # Arrange
    repository = AlertRepository(db_session)

    log = Log(
        timestamp=datetime.now(UTC),
        log_type="windows",
        source="windows.evtx",
        raw_log="Test Log"
    )

    db_session.add(log)
    db_session.commit()

    alert = Alert(
        sid=1001,
        title="Test Alert",
        description="Needs investigation",
        severity="high",
        source="windows",
        detection_method="rule",
        timestamp=datetime.now(UTC),
        log=log,
    )

    saved_alert = repository.save(alert)

    # Act
    repository.resolve_alert(
        saved_alert.alert_id,
        "analyst1"
    )

    resolved = repository.get_by_id(saved_alert.alert_id)

    # Assert
    assert resolved.status == "closed"
    assert resolved.resolved_by == "analyst1"
    assert resolved.resolved_at is not None

def test_delete_alert(db_session):
    # Arrange
    repository = AlertRepository(db_session)

    log = Log(
        timestamp=datetime.now(UTC),
        log_type="windows",
        source="windows.evtx",
        raw_log="Test Log"
    )

    db_session.add(log)
    db_session.commit()

    alert = Alert(
        sid=1001,
        title="Delete Test",
        description="Delete this alert",
        severity="high",
        source="windows",
        detection_method="rule",
        timestamp=datetime.now(UTC),
        log=log,
    )

    saved_alert = repository.save(alert)

    # Act
    repository.delete(saved_alert.alert_id)

    deleted = repository.get_by_id(saved_alert.alert_id)

    # Assert
    assert deleted is None











