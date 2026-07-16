from database.log_repository import LogRepository
from database.models import Log

from query.builder import QueryBuilder
from query.lexer import Lexer
from query.parser import Parser



class SearchService:
    """
    Executes log searches using the custom query language.
    """

    def __init__(
        self,
        repository: LogRepository,
    ):
        self.repository = repository

        self.builder = QueryBuilder()

    def search(
        self,
        query: str,
    ) -> list[Log]:
        """
        Search logs using the custom query language.

        Args:
            query: Search query.

        Returns:
            List of matching logs.
        """

        lexer = Lexer(query)

        tokens = lexer.tokenize()

        parser = Parser(tokens)

        ast = parser.parse()

        expression = self.builder.build(ast)

        return self.repository.search(
            filters=[expression],
        )
    
