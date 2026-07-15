from abc import ABC, abstractmethod

from database.models import Log


class BaseParser(ABC):
    """
    Base class for all log parsers.

    Every parser must implement parse() and return
    a normalized Log model.
    """

    @abstractmethod
    def parse(self, raw_log: str) -> Log:
        """
        Parse a raw log entry.

        Args:
            raw_log: Raw log string.

        Returns:
            Log: Normalized log model.
        """
        raise NotImplementedError