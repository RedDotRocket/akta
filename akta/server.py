from fastapi import APIRouter, FastAPI, Request

from akta.config import settings
from akta.logging import get_logger, request_id_middleware
from akta.vdr.database import create_tables as create_vdr_tables
from akta.vdr.router import router as vdr_router
from akta.test_agent.router import router as agent_router

logger = get_logger(__name__)

def create_app() -> FastAPI:
    """
    Creates and configures the FastAPI application instance.

    This includes setting up the application title, debug mode based on settings,
    adding request ID middleware, and including API routers.

    Returns:
        FastAPI: The configured FastAPI application instance.
    """
    create_vdr_tables()

    app = FastAPI(
        title=settings.app_name,
        debug=settings.debug,
    )

    @app.middleware("http")
    async def add_request_id(request: Request, call_next):
        """Middleware to add a unique request ID to each incoming request and log it."""
        request_id: str = request_id_middleware(request)
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

    api_v1 = APIRouter(prefix="/api/v1", tags=["v1"])

    api_v1.include_router(vdr_router, tags=["Verifiable Credential Registry Endpoints"])

    api_v1.include_router(agent_router, tags=["Agent Endpoints"])

    app.include_router(api_v1)

    @app.get("/health", tags=["Health Check"])
    async def health_check():
        logger.info("Health check endpoint was called.")
        return {"status": "ok", "app_name": settings.app_name, "debug_mode": settings.debug}

    return app

app = create_app()
