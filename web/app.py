from flask import (
    Flask,
    flash,
    render_template,
    request,
    redirect,
    url_for,
)

import os
import tempfile
import math

from services.ingestion_service import IngestionService

from database.database import SessionLocal
from database.log_repository import LogRepository
from database.models import Log

from services.dashboard_service import DashboardService
from services.search_service import SearchService

from web.api import init_api


def create_app() -> Flask:
    """
    Create and configure the Flask application.
    """

    app = Flask(__name__)
    app.secret_key = "security-log-analyzer-secret-key"

    session = SessionLocal()

    repository = LogRepository(session)
    
    ingestion_service = IngestionService(
        log_repository=repository,
    )

    dashboard_service = DashboardService(
        repository=repository,
    )
    

    search_service = SearchService(
        repository=repository,
    )

    api = init_api(
        dashboard_service=dashboard_service,
        search_service=search_service,
    )

    app.register_blueprint(api)

    @app.get("/")
    def dashboard():
        """
        Render the dashboard.
        """

        return render_template(
            "dashboard.html",
            total_logs=dashboard_service.get_total_logs(),
            logs_by_type=dashboard_service.get_logs_by_type(),
            logs_by_status=dashboard_service.get_logs_by_status(),
            recent_logs=dashboard_service.get_recent_logs(limit=10),
        )
    



    @app.route("/upload", methods=["GET", "POST"])
    def upload_page():
        """
        Display the upload page and handle uploads.
        """

        if request.method == "POST":

            uploaded_file = request.files.get("log_file")

            if uploaded_file is None or uploaded_file.filename == "":
                return "No file selected.", 400

            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                uploaded_file.save(temp_file.name)
                temp_path = temp_file.name

            try:
                imported_count = ingestion_service.ingest_file(
                    file_path=temp_path,
                    log_type="windows",
                )

                flash(
                    f"Successfully imported {imported_count} Windows log(s).",
                    "success",
                )

                return redirect(
                    url_for("dashboard")
                )

            except Exception as exc:
                flash(
                    str(exc),
                    "error",
                )

                return redirect(
                    url_for("upload_page")
                )

            finally:
                if os.path.exists(temp_path):
                    os.remove(temp_path)

        return render_template(
            "upload.html",
        )
    
    
    @app.get("/logs")
    def logs_page():
        """
        Browse or search logs with database-level pagination.
        """

        query = request.args.get(
            "q",
            "",
        )

        page = request.args.get(
            "page",
            1,
            type=int,
        )

        page_size = 50

        if page < 1:
            page = 1

        if query:
            total_logs = search_service.count(query)

            total_pages = math.ceil(total_logs / page_size)

            if total_pages > 0 and page > total_pages:
                page = total_pages

            logs = search_service.search(
                query=query,
                page=page,
                page_size=page_size,
            )

        else:
            total_logs = repository.count()

            total_pages = math.ceil(total_logs / page_size)

            if total_pages > 0 and page > total_pages:
                page = total_pages

            offset = (page - 1) * page_size

            logs = repository.search(
                order_by=Log.timestamp,
                descending=True,
                limit=page_size,
                offset=offset,
            )

        return render_template(
            "logs.html",
            logs=logs,
            query=query,
            page=page,
            page_size=page_size,
            total_logs=total_logs,
            total_pages=total_pages,
        )
    

    @app.get("/logs/<int:log_id>")
    def log_details(log_id: int):
        """
        Display details for a single log.
        """

        log = repository.get_by_id(log_id)

        if log is None:
            return "Log not found.", 404

        return render_template(
            "log_details.html",
            log=log,
        )
    return app


if __name__ == "__main__":
    app = create_app()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
    )