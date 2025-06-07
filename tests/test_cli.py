from click.testing import CliRunner

from akta.cli import cli


def test_cli_group():
    """Test the main CLI group."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "Acta - Authenticated Knowledge & Trust Architecture for AI Agents" in result.output
    assert "keys" in result.output
    assert "claim" in result.output
    assert "token" in result.output
    assert "registry" in result.output
    assert "vdr" in result.output 