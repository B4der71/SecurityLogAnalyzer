from database.models import Log





from database.models import Log

# ==========================================================
# Authentication Events
# ==========================================================

def parse_successful_login(parser, data, raw_log) -> Log:
    """
    Event ID 4624
    Successful account logon.
    """

    log = parser._build_base_log(data, raw_log)

    log.username = parser._get(
        data,
        *parser.USERNAME_FIELDS,
    )

    log.target_username = parser._get(
        data,
        *parser.TARGET_USERNAME_FIELDS,
    )

    log.domain = parser._get(
        data,
        *parser.DOMAIN_FIELDS,
    )

    log.source_ip = parser._get(
        data,
        *parser.SOURCE_IP_FIELDS,
    )

    log.source_port = parser._normalize_port(
        parser._get(
            data,
            *parser.SOURCE_PORT_FIELDS,
        )
    )

    log.logon_type = parser._normalize_port(
        parser._get(
            data,
            *parser.LOGON_TYPE_FIELDS,
        )
    )

    log.status = "Success"

    return log


def parse_failed_login(parser, data, raw_log) -> Log:
    """
    Event ID 4625
    Failed account logon.
    """

    log = parser._build_base_log(data, raw_log)

    log.username = parser._get(
        data,
        *parser.USERNAME_FIELDS,
    )

    log.target_username = parser._get(
        data,
        *parser.TARGET_USERNAME_FIELDS,
    )

    log.domain = parser._get(
        data,
        *parser.DOMAIN_FIELDS,
    )

    log.source_ip = parser._get(
        data,
        *parser.SOURCE_IP_FIELDS,
    )

    log.source_port = parser._normalize_port(
        parser._get(
            data,
            *parser.SOURCE_PORT_FIELDS,
        )
    )

    log.logon_type = parser._normalize_port(
        parser._get(
            data,
            *parser.LOGON_TYPE_FIELDS,
        )
    )

    log.status = "Failure"

    return log




# ==========================================================
# Sysmon Events
# ==========================================================

# Future:
# def parse_process_creation(...):
#     ...


# ==========================================================
# Registry Events
# ==========================================================

# Future:
# def parse_registry_set(...):
#     ...


# ==========================================================
# Generic Events
# ==========================================================





def parse_generic(parser, data, raw_log) -> Log:
    """
    Parse unsupported Windows events.
    """

    log = parser._build_base_log(data, raw_log)

    log.username = parser._get(
        data,
        *parser.USERNAME_FIELDS,
    )

    log.target_username = parser._get(
        data,
        *parser.TARGET_USERNAME_FIELDS,
    )

    log.domain = parser._get(
        data,
        *parser.DOMAIN_FIELDS,
    )

    log.source_ip = parser._get(
        data,
        *parser.SOURCE_IP_FIELDS,
    )

    log.source_port = parser._normalize_port(
        parser._get(
            data,
            *parser.SOURCE_PORT_FIELDS,
        )
    )

    log.image = parser._get(
        data,
        *parser.IMAGE_FIELDS,
    )

    log.parent_image = parser._get(
        data,
        *parser.PARENT_IMAGE_FIELDS,
    )

    log.command_line = parser._get(
        data,
        *parser.COMMAND_LINE_FIELDS,
    )

    log.status = parser._get(
        data,
        "Status",
        default="Unknown",
    )

    log.process_id = parser._normalize_port(
        parser._get(
            data,
            *parser.PROCESS_ID_FIELDS,
        )
    )

    log.parent_process_id = parser._normalize_port(
        parser._get(
            data,
            *parser.PARENT_PROCESS_ID_FIELDS,
        )
    )

    log.logon_type = parser._normalize_port(
        parser._get(
            data,
            *parser.LOGON_TYPE_FIELDS,
        )
    )

    return log





