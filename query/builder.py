from sqlalchemy import (
    and_,
    or_,
)

from database.models import Log

from query.parser import (
    ASTNode,
    ComparisonNode,
    LogicalNode,
)

FIELD_MAP = {
    "log_id": Log.log_id,

    "timestamp": Log.timestamp,
    "created_at": Log.created_at,

    "log_type": Log.log_type,
    "source": Log.source,

    "event_id": Log.event_id,

    "username": Log.username,
    "hostname": Log.hostname,

    "protocol": Log.protocol,

    "source_ip": Log.source_ip,
    "source_port": Log.source_port,

    "destination_ip": Log.destination_ip,
    "destination_port": Log.destination_port,

    "status": Log.status,

    "raw_log": Log.raw_log,
}

FIELD_TYPES = {
    "log_id": int,
    "event_id": int,

    "source_port": int,
    "destination_port": int,

    "timestamp": str,
    "created_at": str,

    "log_type": str,
    "source": str,
    "username": str,
    "hostname": str,
    "protocol": str,
    "source_ip": str,
    "destination_ip": str,
    "status": str,
    "raw_log": str,
}


class QueryBuilder:
    """
    Converts an AST into SQLAlchemy filter expressions.
    """

    def __init__(self):
        pass
    
    def _convert_value(
        self,
        field: str,
        value: str,
    ):
        """
        Convert a query value to the appropriate Python type.
        """

        converter = FIELD_TYPES.get(field)

        if converter is None:
            return value

        try:
            return converter(value)

        except (TypeError, ValueError):
            raise ValueError(
                f"Invalid value '{value}' for field '{field}'."
            )
        
    
    def build(
        self,
        node: ASTNode,
    ):
        """
        Convert an AST into a SQLAlchemy filter expression.
        """

        if isinstance(node, ComparisonNode):
            return self._build_comparison(node)

        if isinstance(node, LogicalNode):
            return self._build_logical(node)

        raise TypeError(
            f"Unsupported AST node: {type(node).__name__}"
        )
    

    def _build_comparison(
        self,
        node: ComparisonNode,
    ):
        """
        Build a SQLAlchemy comparison expression.
        """

        column = FIELD_MAP.get(node.field)

        if column is None:
            raise ValueError(
                f"Unknown field: {node.field}"
            )

        value = self._convert_value(
            node.field,
            node.value,
        )

        match node.operator:

            case "=":
                return column == value

            case "!=":
                return column != value

            case ">":
                return column > value

            case ">=":
                return column >= value

            case "<":
                return column < value

            case "<=":
                return column <= value

            case _:
                raise ValueError(
                    f"Unsupported operator: {node.operator}"
                )
    def _build_logical(
        self,
        node: LogicalNode,
    ):
        """
        Build a SQLAlchemy logical expression.
        """

        left = self.build(node.left)
        right = self.build(node.right)

        match node.operator.upper():

            case "AND":
                return and_(left, right)

            case "OR":
                return or_(left, right)

            case _:
                raise ValueError(
                    f"Unsupported logical operator: {node.operator}"
                )
            

