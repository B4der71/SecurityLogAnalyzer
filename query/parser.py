from dataclasses import dataclass

from query.lexer import (
    Token,
    TokenType,
)


class ASTNode:
    """
    Base class for all Abstract Syntax Tree nodes.
    """


@dataclass(slots=True)
class ComparisonNode(ASTNode):
    """
    Represents a comparison.

    Example:
        event_id = 4625
    """

    field: str
    operator: str
    value: str


@dataclass(slots=True)
class LogicalNode(ASTNode):
    """
    Represents a logical expression.

    Example:
        event_id = 4625 AND status = "Failure"
    """

    operator: str
    left: ASTNode
    right: ASTNode

class Parser:
    """
    Converts a list of tokens into an Abstract Syntax Tree.
    """

    def __init__(
        self,
        tokens: list[Token],
    ):
        self.tokens = tokens
        self.position = 0

    def _current(self) -> Token:
        """
        Return the current token without consuming it.
        """

        if self.position >= len(self.tokens):
            return self.tokens[-1]

        return self.tokens[self.position]
    def _advance(self) -> Token:
        """
        Consume and return the current token.
        """

        token = self._current()

        if self.position < len(self.tokens):
            self.position += 1

        return token
    
    def _match(
        self,
        *token_types: TokenType,
    ) -> bool:
        """
        Return True if the current token matches one of the given types.
        """

        return self._current().type in token_types


    def _expect(
        self,
        token_type: TokenType,
    ) -> Token:
        """
        Consume and return the expected token.
        """

        token = self._current()

        if token.type != token_type:
            raise ValueError(
                f"Expected {token_type.name}, got {token.type.name}"
            )

        self._advance()

        return token

    def _parse_comparison(self) -> ComparisonNode:
        """
        Parse a comparison expression.

        Example:
            event_id = 4625
        """

        field = self._expect(TokenType.IDENTIFIER).value

        operator = self._advance()

        if operator.type not in (
            TokenType.EQ,
            TokenType.NE,
            TokenType.GT,
            TokenType.GE,
            TokenType.LT,
            TokenType.LE,
        ):
            raise ValueError(
                f"Expected comparison operator, got {operator.type.name}"
            )

        value = self._advance()

        if value.type not in (
            TokenType.NUMBER,
            TokenType.STRING,
            TokenType.IDENTIFIER,
        ):
            raise ValueError(
                f"Expected value, got {value.type.name}"
            )

        return ComparisonNode(
            field=field,
            operator=operator.value,
            value=value.value,
        )

    def _parse_expression(self) -> ASTNode:
        """
        Parse a logical expression.

        Example:
            event_id = 4625 AND status = "Failure"
        """

        node = self._parse_primary()

        while self._match(
            TokenType.AND,
            TokenType.OR,
        ):

            operator = self._advance().value

            right = self._parse_primary()

            node = LogicalNode(
                operator=operator,
                left=node,
                right=right,
            )

        return node
    

    def parse(self) -> ASTNode:
        """
        Parse the token stream into an AST.
        """

        ast = self._parse_expression()

        self._expect(TokenType.EOF)

        return ast
    
    def _parse_primary(self) -> ASTNode:
        """
        Parse a primary expression.

        A primary expression is either:
            - A comparison
            - A parenthesized expression
        """

        if self._match(TokenType.LPAREN):

            self._advance()

            node = self._parse_expression()

            self._expect(TokenType.RPAREN)

            return node

        return self._parse_comparison()
