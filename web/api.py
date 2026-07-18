from flask import (
    Blueprint,
    jsonify,
    request,
)

from services.dashboard_service import DashboardService
from services.search_service import SearchService


api = Blueprint(
    "api",
    __name__,
    url_prefix="/api",
)

def init_api(
    dashboard_service: DashboardService,
    search_service: SearchService,
):
    """
    Initialize API routes with application services.
    """

    @api.get("/dashboard")
    def get_dashboard():
        """
        Return dashboard statistics.
        """

        data = {
            "total_logs": dashboard_service.get_total_logs(),
            "logs_by_type": dashboard_service.get_logs_by_type(),
            "logs_by_status": dashboard_service.get_logs_by_status(),
        }

        return jsonify(data)


    @api.get("/logs/search")
    def search_logs():
        """
        Search logs using the custom query language.
        """

        query = request.args.get(
            "q",
            type=str,
        )

        if not query:
            return jsonify(
                {
                    "error": "Missing search query parameter 'q'."
                }
            ), 400

        try:
            logs = search_service.search(query)

            results = []

            for log in logs:
                results.append(
                    {
                        "log_id": log.log_id,
                        "timestamp": log.timestamp.isoformat(),
                        "log_type": log.log_type,
                        "source": log.source,
                        "event_id": log.event_id,
                        "username": log.username,
                        "hostname": log.hostname,
                        "protocol": log.protocol,
                        "source_ip": (
                            str(log.source_ip)
                            if log.source_ip
                            else None
                        ),
                        "source_port": log.source_port,
                        "destination_ip": (
                            str(log.destination_ip)
                            if log.destination_ip
                            else None
                        ),
                        "destination_port": log.destination_port,
                        "status": log.status,
                        "raw_log": log.raw_log,
                    }
                )

            return jsonify(
                {
                    "query": query,
                    "count": len(results),
                    "results": results,
                }
            )

        except (ValueError, SyntaxError) as error:
            return jsonify(
                {
                    "error": str(error)
                }
            ), 400


    return api
