import json
from datetime import datetime
from typing import Any

from database.models import Log
from parsers.parser import BaseParser


class WindowsParser(BaseParser):
    """
    Parses Windows Security Event logs and converts them
    into normalized Log objects.
    """

    # ==========================================================
    # Field Aliases
    # ==========================================================

    EVENT_ID_FIELDS = (
        "EventID",
        "EventId",
        "event_id",
    )

    TIMESTAMP_FIELDS = (
        "TimeCreated",
        "Timestamp",
        "@timestamp",
    )

    HOSTNAME_FIELDS = (
        "Computer",
        "Hostname",
        "MachineName",
    )

    USERNAME_FIELDS = (
        "TargetUserName",
        "SubjectUserName",
        "User",
        "AccountName",
    )

    SOURCE_IP_FIELDS = (
        "IpAddress",
        "ClientAddress",
        "SourceAddress",
    )

    SOURCE_PORT_FIELDS = (
        "IpPort",
        "SourcePort",
    )

    # ==========================================================
    # Constructor
    # ==========================================================

    def __init__(self):
        self.event_handlers = self._initialize_event_handlers()

    # ==========================================================
    # Initialization
    # ==========================================================

    def _initialize_event_handlers(self) -> dict[int, callable]:
        """
        Register supported Windows Event handlers.
        """

        handlers = {}

        # Authentication Events
        handlers.update({
            4624: self._parse_successful_login,
            4625: self._parse_failed_login,
        })

        return handlers

    # ==========================================================
    # Public API
    # ==========================================================

    def parse(self, raw_log: str) -> Log:
        """
        Parse a raw Windows event.

        Args:
            raw_log: Raw Windows event as a JSON string.

        Returns:
            Parsed Log model.
        """

        data = json.loads(raw_log)

        event_id = self._get(
            data,
            *self.EVENT_ID_FIELDS,
        )

        handler = self.event_handlers.get(event_id)

        if handler:
            return handler(data, raw_log)

        return self._parse_generic(data, raw_log)

    # ==========================================================
    # Shared Helpers
    # ==========================================================

    def _get(
        self,
        data: dict[str, Any],
        *keys: str,
        default=None,
    ):
        """
        Return the first non-empty value found for the given keys.
        """

        for key in keys:
            value = data.get(key)

            if value not in (None, ""):
                return value

        return default

    def _parse_timestamp(
        self,
        data: dict[str, Any],
    ) -> datetime | None:
        """
        Convert a timestamp string into a datetime object.
        """

        timestamp = self._get(
            data,
            *self.TIMESTAMP_FIELDS,
        )

        if timestamp is None:
            return None

        try:
            return datetime.fromisoformat(timestamp)
        except ValueError:
            return None

    def _build_base_log(
        self,
        data: dict[str, Any],
        raw_log: str,
    ) -> Log:
        """
        Build the common Log object shared by all Windows events.
        """

        return Log(
            timestamp=self._parse_timestamp(data),
            log_type="windows",
            source="Windows Security Log",
            event_id=self._get(
                data,
                *self.EVENT_ID_FIELDS,
            ),
            hostname=self._get(
                data,
                *self.HOSTNAME_FIELDS,
            ),
            raw_log=raw_log,
        )

    # ==========================================================
    # Authentication Events
    # ==========================================================

    def _parse_successful_login(
        self,
        data: dict[str, Any],
        raw_log: str,
    ) -> Log:
        """
        Event ID 4624
        Successful account logon.
        """

        log = self._build_base_log(data, raw_log)

        log.username = self._get(
            data,
            *self.USERNAME_FIELDS,
        )

        log.source_ip = self._get(
            data,
            *self.SOURCE_IP_FIELDS,
        )

        log.source_port = self._get(
            data,
            *self.SOURCE_PORT_FIELDS,
        )

        log.status = "Success"

        return log

    def _parse_failed_login(
        self,
        data: dict[str, Any],
        raw_log: str,
    ) -> Log:
        """
        Event ID 4625
        Failed account logon.
        """

        log = self._build_base_log(data, raw_log)

        log.username = self._get(
            data,
            *self.USERNAME_FIELDS,
        )

        log.source_ip = self._get(
            data,
            *self.SOURCE_IP_FIELDS,
        )

        log.source_port = self._get(
            data,
            *self.SOURCE_PORT_FIELDS,
        )

        log.status = "Failure"

        return log

    # ==========================================================
    # Generic Events
    # ==========================================================

    def _parse_generic(
        self,
        data: dict[str, Any],
        raw_log: str,
    ) -> Log:
        """
        Parse unsupported Windows events.
        """

        log = self._build_base_log(data, raw_log)

        log.username = self._get(
            data,
            *self.USERNAME_FIELDS,
        )

        log.source_ip = self._get(
            data,
            *self.SOURCE_IP_FIELDS,
        )

        log.source_port = self._get(
            data,
            *self.SOURCE_PORT_FIELDS,
        )

        log.status = self._get(
            data,
            "Status",
            default="Unknown",
        )

        return log