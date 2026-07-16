from database.log_repository import LogRepository
from database.models import Log

class DashboardService:
    """
    Provides dashboard statistics and recent log information.
    """

    def __init__(
        self,
        repository: LogRepository,
    ):
        self.repository = repository

    def get_total_logs(
        self,
    ) -> int:
        """
        Return the total number of logs.
        """
        return self.repository.count()


    def get_logs_by_type(
        self,
    ) -> dict[str, int]:
        """
        Return log counts grouped by log type.
        """
        return self.repository.count_by_log_type()


    def get_logs_by_status(
        self,
    ) -> dict[str, int]:
        """
        Return log counts grouped by status.
        """
        return self.repository.count_by_status()


    def get_recent_logs(
        self,
        limit: int = 10,
    ) -> list[Log]:
        """
        Return the most recent logs.
        """
        return self.repository.get_recent(
        limit=limit,
    )