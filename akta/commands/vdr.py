import click
import uvicorn

from akta.config import settings

@click.group("vdr")
def vdr():
    """Akta Verifiable Data Registry Server Management CLI."""
    pass


@vdr.command()
@click.option("--host", default=settings.host, show_default=True,
              help="Host to bind the server to.")
@click.option("--port", default=settings.port, show_default=True,
              help="Port to bind the server to.")
@click.option("--reload/--no-reload", default=settings.reload, show_default=True,
              help="Enable auto-reload (for development).")
def serve(host, port, reload):
    """Starts the Akta Verifiable Data Registry server."""
    click.echo(f"Starting server on http://{host}:{port}")
    app_string = "akta.server:app"

    uvicorn.run(
        app_string,
        host=host,
        port=port,
        reload=reload,
        log_config=None,
        use_colors=False,
    )