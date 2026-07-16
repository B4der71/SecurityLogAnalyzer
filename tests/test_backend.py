from pathlib import Path

from database.database import SessionLocal
from database.log_repository import LogRepository

from parsers.parser_factory import ParserFactory

from services.ingestion_service import IngestionService
from services.search_service import SearchService
from services.dashboard_service import DashboardService




LOG_FILE = Path(
    "data/raw_logs/windows.json"
)

LOG_TYPE = "windows"



session = SessionLocal()

repository = LogRepository(session)

parser_factory = ParserFactory()

ingestion_service = IngestionService(
    parser_factory=parser_factory,
    log_repository=repository,
)

search_service = SearchService(
    repository=repository,
)


print("=" * 60)
print("Testing database connection...")
print("=" * 60)

repository.search(limit=1)

print("✓ Database connection successful\n")



print("=" * 60)
print("Testing log ingestion...")
print("=" * 60)

count = ingestion_service.ingest_file(
    file_path=str(LOG_FILE),
    log_type=LOG_TYPE,
)

print(f"✓ Imported {count} logs\n")



print("=" * 60)
print("Testing search service...")
print("=" * 60)

queries = [

    'event_id = 4625',

    'status = "Failure"',

    'event_id = 4625 AND status = "Failure"',

]



for query in queries:

    print(f"Query: {query}")

    logs = search_service.search(query)

    print(f"Results: {len(logs)}")

    print("-" * 60)


print()
print("=" * 60)
print("Backend integration test completed successfully.")
print("=" * 60)


for log in logs:
    print(
        f"[{log.log_id}] "
        f"EventID={log.event_id} "
        f"User={log.username} "
        f"Status={log.status}"
    )



print()
print("=" * 60)
print("Testing repository statistics...")
print("=" * 60)

print(f"Total logs: {repository.count()}")

print()

print("Logs by type:")
for log_type, count in repository.count_by_log_type().items():
    print(f"  {log_type}: {count}")

print()

print("Logs by status:")
for status, count in repository.count_by_status().items():
    print(f"  {status}: {count}")

print()

print("Recent logs:")

for log in repository.get_recent(limit=5):
    print(
        f"[{log.log_id}] "
        f"{log.timestamp} "
        f"{log.event_id} "
        f"{log.username}"
    )





dashboard_service = DashboardService(
    repository=repository,
)




print()
print("=" * 60)
print("Testing dashboard service...")
print("=" * 60)

print(f"Total logs: {dashboard_service.get_total_logs()}")

print()

print("Logs by type:")
for log_type, count in dashboard_service.get_logs_by_type().items():
    print(f"  {log_type}: {count}")

print()

print("Logs by status:")
for status, count in dashboard_service.get_logs_by_status().items():
    print(f"  {status}: {count}")

print()

print("Recent logs:")

for log in dashboard_service.get_recent_logs(limit=5):
    print(
        f"[{log.log_id}] "
        f"{log.timestamp} "
        f"{log.event_id} "
        f"{log.username} "
        f"{log.status}"
    )