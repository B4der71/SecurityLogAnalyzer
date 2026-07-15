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

    def add(self, log: Log) -> Log:
        """
        Save a new log to the database.

        Args:
            log: Log object to save.

        Returns:
            The saved Log object.
        """
        

        try:
            self.session.add(log)
            self.session.commit()
            self.session.refresh(log)

            return log

        except SQLAlchemyError:
            self.session.rollback()
            raise

        
    
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

    def get_recent_logs(self, limit: int = 100) -> list[Log]:
        """
        Retrieve the most recent logs.

        Args:
            limit: Maximum number of logs to return.

        Returns:
            A list of recent Log objects.
        """
        

        
        statement = (
            select(Log)
            .order_by(desc(Log.timestamp))
            .limit(limit)
        )

        result = self.session.execute(statement)

        return result.scalars().all()

        

    def count(self) -> int:
        """
        Return the total number of logs.

        Returns:
            Total number of logs.
        """
        

        
        statement = (
            select(func.count())
            .select_from(Log)
         )

        result = self.session.execute(statement)

        return result.scalar_one()

        

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

        