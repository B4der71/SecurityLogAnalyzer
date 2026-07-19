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
        page: int = 1,
        page_size: int = 50,
    ) -> list[Log]:
        """
        Search logs using the custom query language.
        """

        lexer = Lexer(query)

        tokens = lexer.tokenize()

        parser = Parser(tokens)

        ast = parser.parse()

        expression = self.builder.build(ast)

        offset = (page - 1) * page_size

        return self.repository.search(
            filters=[expression],
            order_by=Log.timestamp,
            descending=False,
            limit=page_size,
            offset=offset,
        )
    
    def count(
        self,
        query: str,
    ) -> int:
        """
        Count logs matching the custom search query.
        """

        lexer = Lexer(query)

        tokens = lexer.tokenize()

        parser = Parser(tokens)

        ast = parser.parse()

        expression = self.builder.build(ast)

        return self.repository.count_search(
            filters=[expression],
        )