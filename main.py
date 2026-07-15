from database.database import SessionLocal
from database.log_repository import LogRepository
from services.ingestion_service import IngestionService


def main():

    session = SessionLocal()

    try:

        repository = LogRepository(session)

        service = IngestionService(repository)

        imported = service.ingest_file(
            file_path="data/raw_logs/windows.json",
            log_type="windows",
        )

        print(f"Imported {imported} log(s).")

    finally:
        session.close()


if __name__ == "__main__":
    main()