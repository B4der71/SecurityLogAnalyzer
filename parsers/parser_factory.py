#from parsers.apache_parser import ApacheParser
#from parsers.linux_parser import LinuxParser
from parsers.windows.windows_parser import WindowsParser


class ParserFactory:
    """
    Factory responsible for creating parser instances.

    Each parser knows how to parse one log source.
    """

    _PARSERS = {
        "windows": WindowsParser,
        #"linux": LinuxParser,
        #"apache": ApacheParser,
    }

    @classmethod
    def create_parser(cls, log_type: str):
        """
        Create a parser for the requested log type.

        Args:
            log_type: Log source type.

        Returns:
            A parser instance.

        Raises:
            ValueError:
                If the log type is not supported.
        """

        if not log_type:
            raise ValueError("Log type cannot be empty.")

        parser_class = cls._PARSERS.get(log_type.lower())

        if parser_class is None:
            supported = ", ".join(sorted(cls._PARSERS.keys()))

            raise ValueError(
                f"Unsupported log type '{log_type}'. "
                f"Supported types: {supported}"
            )

        return parser_class()