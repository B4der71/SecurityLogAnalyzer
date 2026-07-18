from sqlalchemy import (
    select,
    desc,
    func,
)

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.sql.elements import ColumnElement

from database.database import SessionLocal
from database.models import Log
class LogRepository:

    def __init__(self, session):
        self.session = session
    
    def commit(self) -> None:
        """
        Commit the current transaction.
        """

        try:
            self.session.commit()

        except SQLAlchemyError:
            self.session.rollback()
            raise
    
    def rollback(self) -> None:
        """
        Roll back the current transaction.
        """

        self.session.rollback()

    def add(self, log: Log) -> None:
        """
        Stage a log for insertion.

        The log is not committed until commit() is called.
        """

        self.session.add(log)
 
    
    def get_by_id(self, log_id: int) -> Log | None:
        """
        Retrieve a log by its ID.

        Args:
            log_id: Primary key of the log.

        Returns:
            Log object if found, otherwise None.
        """
        return self.session.get(Log, log_id)
          

    def get_all(self) -> list[Log]:
        """
        Retrieve all logs.

        Returns:
            A list of Log objects.
        """

        statement = select(Log)

        result = self.session.execute(statement)

        return result.scalars().all()


    def search(
        self,
        filters: list[ColumnElement[bool]] | None = None,
        order_by=None,
        descending: bool = False,
        limit: int | None = None,
        offset: int | None = None,
    ) -> list[Log]:
        """
        Search logs using SQLAlchemy filter expressions.

        Args:
            filters: List of SQLAlchemy filter expressions.
            order_by: Log model column used for sorting.
            descending: Sort results in descending order.
            limit: Maximum number of rows to return.
            offset: Number of rows to skip.

        Returns:
            A list of matching Log objects.
        """
        

        
        statement = select(Log)

        if filters:
            statement = statement.where(*filters)

        if order_by is not None:
            if descending:
                statement = statement.order_by(desc(order_by))
            else:
                statement = statement.order_by(order_by)

        if offset is not None:
            statement = statement.offset(offset)

        if limit is not None:
            statement = statement.limit(limit)

        result = self.session.execute(statement)

        return result.scalars().all()

    def count(self) -> int:
        """
        Return the total number of logs.
        """

        statement = select(
            func.count(Log.log_id)
        )

        return self.session.scalar(statement) or 0
    
    def count_search(
        self,
        filters: list[ColumnElement[bool]] | None = None,
    ) -> int:
        """
        Count logs matching the given filters.
        """

        statement = select(
            func.count(Log.log_id)
        )

        if filters:
            statement = statement.where(*filters)

        return self.session.scalar(statement) or 0
    
    def count_by_log_type(self) -> dict[str, int]:
        """
        Return the number of logs for each log type.
        """

        statement = (
            select(
                Log.log_type,
                func.count(Log.log_id),
            )
            .group_by(Log.log_type)
            .order_by(Log.log_type)
        )

        result = self.session.execute(statement)

        return {
            log_type: count
            for log_type, count in result
        }
    
    def count_by_status(self) -> dict[str, int]:
        """
        Return the number of logs for each status.
        """

        statement = (
            select(
                Log.status,
                func.count(Log.log_id),
            )
            .group_by(Log.status)
            .order_by(Log.status)
        )

        result = self.session.execute(statement)

        return {
            status: count
            for status, count in result
        }
    
    def get_recent(
        self,
        limit: int = 10,
    ) -> list[Log]:
        """
        Return the most recent logs.
        """

        return self.search(
            order_by=Log.timestamp,
            descending=True,
            limit=limit,
        )