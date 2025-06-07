from unittest.mock import patch
from click.testing import CliRunner
from akta.commands.vdr import vdr
from akta.config import settings


@patch("uvicorn.run")
def test_vdr_serve_default(mock_uvicorn_run):
    """Test `vdr serve` with default parameters."""
    runner = CliRunner()
    result = runner.invoke(vdr, ["serve"])

    assert result.exit_code == 0
    assert f"Starting server on http://{settings.host}:{settings.port}" in result.output
    mock_uvicorn_run.assert_called_once_with(
        "akta.server:app",
        host=settings.host,
        port=settings.port,
        reload=settings.reload,
        log_config=None,
        use_colors=False,
    )


@patch("uvicorn.run")
def test_vdr_serve_custom_params(mock_uvicorn_run):
    """Test `vdr serve` with custom parameters."""
    runner = CliRunner()
    host = "0.0.0.0"
    port = 8888
    result = runner.invoke(vdr, ["serve", "--host", host, "--port", str(port), "--reload"])

    assert result.exit_code == 0
    assert f"Starting server on http://{host}:{port}" in result.output
    mock_uvicorn_run.assert_called_once_with(
        "akta.server:app",
        host=host,
        port=port,
        reload=True,
        log_config=None,
        use_colors=False,
    )


@patch("uvicorn.run")
def test_vdr_serve_no_reload(mock_uvicorn_run):
    """Test `vdr serve` with --no-reload."""
    runner = CliRunner()
    result = runner.invoke(vdr, ["serve", "--no-reload"])

    assert result.exit_code == 0
    mock_uvicorn_run.assert_called_once_with(
        "akta.server:app",
        host=settings.host,
        port=settings.port,
        reload=False,
        log_config=None,
        use_colors=False,
    ) 