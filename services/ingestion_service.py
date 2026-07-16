from pathlib import Path

from database.log_repository import LogRepository
from database.models import Log
from parsers.parser_factory import ParserFactory


class IngestionService:
    """
    Service responsible for importing logs into the system.

    Responsibilities:
        - Select the appropriate parser.
        - Parse raw log entries.
        - Store parsed logs in the database.
        - Return the stored Log objects.

    This service does NOT:
        - Detect attacks
        - Generate alerts
        - Run machine learning models
        - Search logs
        - Generate reports
    """

    def __init__(
        self,
        log_repository: LogRepository,
        parser_factory=ParserFactory,
    ):
        """
        Initialize the ingestion service.

        Args:
            log_repository: Repository responsible for persisting logs.
            parser_factory: Factory responsible for creating parsers.
        """

        self.log_repository = log_repository
        self.parser_factory = parser_factory

    def ingest_log(
        self,
        raw_log: str,
        log_type: str,
    ) -> Log:
        """
        Parse and store a single log entry.

        Args:
            raw_log: Raw log entry.
            log_type: Log source type
                      (windows, linux, apache, zeek, ...)

        Returns:
            The stored Log object.
        """

        parser = self.parser_factory.create_parser(log_type)

        log = parser.parse(raw_log)

        self.log_repository.add(log)

        return log

    def ingest_logs(
        self,
        raw_logs: list[str],
        log_type: str,
    ) -> list[Log]:
        """
        Parse and store multiple log entries.

        Args:
            raw_logs: List of raw log entries.
            log_type: Log source type.

        Returns:
            List of stored Log objects.
        """

        logs = []

        try:

            for raw_log in raw_logs:
                log = self.ingest_log(
                    raw_log=raw_log,
                    log_type=log_type,
                )

                logs.append(log)

            self.log_repository.commit()

            return logs

        except Exception:
            self.log_repository.rollback()
            raise
    def ingest_file(
        self,
        file_path: str,
        log_type: str,
    ) -> int:
        """
        Parse and store all logs from a file.

        Each non-empty line is treated as one log entry.

        Args:
            file_path: Path to the log file.
            log_type: Log source type.

        Returns:
            Number of imported log entries.
        """

        path = Path(file_path)

        raw_logs = []

        with path.open(
            mode="r",
            encoding="utf-8",
        ) as file:

            for line in file:

                raw_log = line.strip()

                if raw_log:
                    raw_logs.append(raw_log)

        logs = self.ingest_logs(
            raw_logs=raw_logs,
            log_type=log_type,
        )

        return len(logs)