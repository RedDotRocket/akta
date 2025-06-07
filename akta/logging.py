import logging
from typing import Optional
from uuid import uuid4

from fastapi import Request

from akta.config import settings

"""
Configures and provides logging for the application.

This module sets up structured JSON logging by default (or text logging if configured),
integrates with Uvicorn loggers, and provides a middleware for adding a unique
request ID to each log entry associated with a request.
"""

def configure_logging():
    """Configures application-wide logging.

    Sets up logging format (JSON or text), level, and handlers based on `settings`.
    It configures handlers for the root logger, Uvicorn loggers (uvicorn, uvicorn.error,
    uvicorn.access), and a specific application logger (e.g., 'orbit' or a more generic name like 'app').
    """
    log_format = settings.log_format.lower()
    if log_format not in ["json", "text"]:
        # Fallback to text if an invalid format is specified, and log a warning.
        # This requires a basic logger setup temporarily or print.
        print(f"WARNING: Invalid log_format '{settings.log_format}' in settings. Falling back to 'text'.")
        log_format = "text"

    logging_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "json": {
                "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
                # Example format: %(asctime)s %(levelname)s %(name)s %(module)s %(funcName)s %(lineno)d %(message)s %(request_id)s
                # Adjust format to include fields you want by default from LogRecord, plus custom ones added via 'extra'
                "format": "%(asctime)s %(levelname)s %(name)s %(message)s %(request_id)s",
                "rename_fields": {"levelname": "level", "asctime": "timestamp"},
            },
            "text": {
                # Basic text format, can be made more detailed
                "format": "%(asctime)s - %(name)s - %(levelname)s - [%(request_id)s] - %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S",
            }
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": log_format, # Use validated log_format
                "level": settings.log_level.upper(), # Ensure level is uppercase
                "stream": "ext://sys.stdout" # Explicitly send to stdout
            }
        },
        "loggers": {
            "uvicorn": { # Uvicorn's own logger for server events
                "handlers": ["console"],
                "level": settings.log_level.upper(),
                "propagate": False, # Don't pass to root logger if handled here
            },
            "uvicorn.error": { # Uvicorn's error logger
                "handlers": ["console"],
                "level": settings.log_level.upper(),
                "propagate": False,
            },
            "uvicorn.access": { # Uvicorn's access logger (request/response)
                "handlers": ["console"],
                "level": settings.log_level.upper(),
                "propagate": False,
            },
            # Application-specific logger. 'akta' seems appropriate from get_logger default.
            # You might want a more general name if this logging module is shared, e.g., 'app_logger'
            settings.app_name: { # Using app_name from settings for the main app logger
                "handlers": ["console"],
                "level": settings.log_level.upper(),
                "propagate": False, # Usually false for app loggers if they have their own handlers
            },
            "akta": { # Explicitly configure the default logger from get_logger
                "handlers": ["console"],
                "level": settings.log_level.upper(),
                "propagate": False,
            }
        },
        # Configure the root logger to catch any logs not handled by specific loggers
        "root": {
            "handlers": ["console"],
            "level": settings.log_level.upper(),
        }
    }
    logging.config.dictConfig(logging_config)

def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Get a configured logger instance.

    If `name` is not provided, it defaults to the application name defined in settings,
    or 'akta' as a fallback if app_name is also not set/empty.
    The logger will be configured based on `configure_logging()` setup.

    Args:
        name: The name for the logger. Defaults to `settings.app_name` or 'akta'.

    Returns:
        A configured `logging.Logger` instance.
    """
    default_logger_name = settings.app_name if settings.app_name else "akta"
    logger_name = name or default_logger_name
    return logging.getLogger(logger_name)

def request_id_middleware(request: Request) -> str:
    """FastAPI middleware to generate a unique request ID, log it, and prepare it for response headers.

    This middleware:
    1. Generates a unique UUID4 for the request.
    2. Gets a logger instance (named after `settings.app_name` or 'akta').
    3. Logs an "Incoming request" message including the request ID, path, and method.
       The logger should be configured to handle the `request_id` in its format string if desired.

    Args:
        request: The incoming FastAPI `Request` object.

    Returns:
        str: The generated unique request ID (UUID4 string).
    """
    request_id = str(uuid4())
    # Use the application's default logger name for request logging
    logger = get_logger()

    # Log with extra fields that can be picked up by the formatter
    logger.info(
        f"Incoming request: {request.method} {request.url.path}",
        extra={
            "request_id": request_id,
            "path": str(request.url.path),
            "method": request.method,
            "client_host": request.client.host if request.client else "unknown",
            # Add other request details you might find useful, e.g., headers (carefully, might contain sensitive info)
        }
    )
    return request_id

configure_logging()