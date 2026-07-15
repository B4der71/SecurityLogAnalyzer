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

    def add(self, log: Log) -> Log:
        """
        Save a new log to the database.

        Args:
            log: Log object to save.

        Returns:
            The saved Log object.
        """
        session = SessionLocal()

        try:
            session.add(log)
            session.commit()
            session.refresh(log)

            return log

        except SQLAlchemyError:
            session.rollback()
            raise

        finally:
            session.close()
    
    def get_by_id(self, log_id: int) -> Log | None:
        """
        Retrieve a log by its ID.

        Args:
            log_id: Primary key of the log.

        Returns:
            Log object if found, otherwise None.
        """
        session = SessionLocal()

        try:
            return session.get(Log, log_id)

        finally:
            session.close()

    def get_all(self) -> list[Log]:
        """
        Retrieve all logs.

        Returns:
            A list of Log objects.
        """
        session = SessionLocal()

        try:
            statement = select(Log)
            result = session.execute(statement)

            return result.scalars().all()

        finally:
            session.close()

    def get_recent_logs(self, limit: int = 100) -> list[Log]:
        """
        Retrieve the most recent logs.

        Args:
            limit: Maximum number of logs to return.

        Returns:
            A list of recent Log objects.
        """
        session = SessionLocal()

        try:
            statement = (
                select(Log)
                .order_by(desc(Log.timestamp))
                .limit(limit)
            )

            result = session.execute(statement)

            return result.scalars().all()

        finally:
            session.close()

    def count(self) -> int:
        """
        Return the total number of logs.

        Returns:
            Total number of logs.
        """
        session = SessionLocal()

        try:
            statement = (
                select(func.count())
                .select_from(Log)
            )

            result = session.execute(statement)

            return result.scalar_one()

        finally:
            session.close()

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
        session = SessionLocal()

        try:
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

            result = session.execute(statement)

            return result.scalars().all()

        finally:
            session.close()