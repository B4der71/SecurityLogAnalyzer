from dataclasses import dataclass
from enum import Enum, auto


class TokenType(Enum):
    """
    Supported token types for the query language.
    """

    IDENTIFIER = auto()
    NUMBER = auto()
    STRING = auto()

    EQ = auto()       # =
    NE = auto()       # !=
    GT = auto()       # >
    LT = auto()       # <
    GE = auto()       # >=
    LE = auto()       # <=

    AND = auto()
    OR = auto()

    LPAREN = auto()   # (
    RPAREN = auto()   # )

    EOF = auto()


@dataclass(slots=True)
class Token:
    """
    Represents a single token produced by the lexer.
    """

    type: TokenType
    value: str

    def __repr__(self) -> str:
        return f"Token(type={self.type.name}, value={self.value!r})"


class Lexer:
    """
    Converts a query string into a sequence of tokens.

    Example:
        event_id = 4625 AND status = "Failure"
    """

    def __init__(self, text: str):
        self.text = text
        self.position = 0
        self.length = len(text)

    def tokenize(self) -> list[Token]:
        """
        Convert the input text into a sequence of tokens.
        """

        tokens = []

        while self._peek() is not None:

            self._skip_whitespace()

            current = self._peek()

            if current is None:
                break

            # Identifier / Keyword
            if current.isalpha() or current == "_":
                tokens.append(self._read_identifier())
                continue

            # Number
            if current.isdigit():
                tokens.append(self._read_number())
                continue

            # String
            if current == '"':
                tokens.append(self._read_string())
                continue

            # =
            if current == "=":
                self._advance()
                tokens.append(Token(TokenType.EQ, "="))
                continue

            # !=
            if current == "!":
                self._advance()

                if self._peek() != "=":
                    raise ValueError("Expected '=' after '!'")

                self._advance()

                tokens.append(Token(TokenType.NE, "!="))
                continue

            # >
            if current == ">":
                self._advance()

                if self._peek() == "=":
                    self._advance()
                    tokens.append(Token(TokenType.GE, ">="))
                else:
                    tokens.append(Token(TokenType.GT, ">"))

                continue

            # <
            if current == "<":
                self._advance()

                if self._peek() == "=":
                    self._advance()
                    tokens.append(Token(TokenType.LE, "<="))
                else:
                    tokens.append(Token(TokenType.LT, "<"))

                continue

            # (
            if current == "(":
                self._advance()
                tokens.append(Token(TokenType.LPAREN, "("))
                continue

            # )
            if current == ")":
                self._advance()
                tokens.append(Token(TokenType.RPAREN, ")"))
                continue

            raise ValueError(f"Unexpected character: {current}")

        tokens.append(Token(TokenType.EOF, ""))

        return tokens

    def _peek(self) -> str | None:
            """
            Return the current character without consuming it.
            """

            if self.position >= self.length:
                return None

            return self.text[self.position]

    def _advance(self) -> str | None:
        """
        Consume and return the current character.
        """

        if self.position >= self.length:
            return None

        character = self.text[self.position]

        self.position += 1

        return character

    def _skip_whitespace(self) -> None:
        """
        Skip whitespace characters.
        """

        while (
            self._peek() is not None
            and self._peek().isspace()
        ):
            self._advance()

    def _read_identifier(self) -> Token:
        """
        Read an identifier or keyword.
        """

        value = []

        while (
            self._peek() is not None
            and (
                self._peek().isalnum()
                or self._peek() == "_"
            )
        ):
            value.append(self._advance())

        text = "".join(value)

        if text.upper() == "AND":
            return Token(TokenType.AND, text)

        if text.upper() == "OR":
            return Token(TokenType.OR, text)

        return Token(TokenType.IDENTIFIER, text)
    


    def _read_number(self) -> Token:
        """
        Read a numeric literal.
        """

        value = []

        while (
            self._peek() is not None
            and self._peek().isdigit()
        ):
            value.append(self._advance())

        return Token(
            TokenType.NUMBER,
            "".join(value),
        )
    



    def _read_string(self) -> Token:
        """
        Read a quoted string literal.
        """

        # Consume opening quote
        self._advance()

        value = []

        while (
            self._peek() is not None
            and self._peek() != '"'
        ):
            value.append(self._advance())

        if self._peek() != '"':
            raise ValueError("Unterminated string literal.")

        # Consume closing quote
        self._advance()

        return Token(
            TokenType.STRING,
            "".join(value),
        )
    


