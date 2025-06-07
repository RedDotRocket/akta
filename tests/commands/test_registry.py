import json
from unittest.mock import MagicMock
from click.testing import CliRunner
import httpx
from akta.commands.registry import registry

SIGNED_VC = {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "id": "http://example.edu/credentials/3732",
    "type": ["VerifiableCredential"],
    "issuer": "https://example.edu/issuers/14",
    "issuanceDate": "2010-01-01T19:23:24Z",
    "credentialSubject": {"id": "did:example:ebfeb1f712ebc6f1c276e12ec21"},
    "proof": {
        "type": "Ed25519Signature2020",
        "proofPurpose": "assertionMethod",
        "proofValue": "z...",
    },
}


def test_push_to_vdr_success(mocker, tmp_path):
    """Test `registry push` successful case."""
    mock_post = mocker.patch("httpx.post")
    mock_post.return_value.status_code = 201
    mock_post.return_value.json.return_value = {
        "status": "success",
        "message": "VC published",
    }
    mock_post.return_value.is_success = True

    runner = CliRunner()
    vc_file = tmp_path / "vc.json"
    vc_file.write_text(json.dumps(SIGNED_VC))

    result = runner.invoke(registry, ["push", "--vc-file", str(vc_file)])

    assert result.exit_code == 0
    assert "VC published successfully!" in result.output
    mock_post.assert_called_once()
    sent_json = mock_post.call_args.kwargs["json"]
    assert sent_json["verifiable_credential"] == SIGNED_VC


def test_push_to_vdr_http_error(mocker, tmp_path):
    """Test `registry push` with an HTTP error."""
    mock_post = mocker.patch("httpx.post")
    mock_post.side_effect = httpx.RequestError("Connection error", request=mocker.MagicMock())

    runner = CliRunner()
    vc_file = tmp_path / "vc.json"
    vc_file.write_text(json.dumps(SIGNED_VC))

    result = runner.invoke(registry, ["push", "--vc-file", str(vc_file)])

    assert result.exit_code == 0
    assert "HTTP request error while publishing VC" in result.output


def test_pull_from_vdr_success_pretty(mocker):
    """Test `registry pull` successful case with pretty print."""
    mock_get = mocker.patch("httpx.get")
    mock_get.return_value.status_code = 200
    mock_get.return_value.text = json.dumps(SIGNED_VC)
    mock_get.return_value.raise_for_status.return_value = None

    runner = CliRunner()
    result = runner.invoke(registry, ["pull", "--vc-id", "123", "--pretty"])

    assert result.exit_code == 0
    # The output should be the pretty-printed JSON
    assert json.loads(result.output) == SIGNED_VC


def test_pull_from_vdr_success_raw(mocker):
    """Test `registry pull` successful case with raw print."""
    mock_get = mocker.patch("httpx.get")
    mock_get.return_value.status_code = 200
    raw_json = json.dumps(SIGNED_VC, separators=(",", ":"))
    mock_get.return_value.text = raw_json
    mock_get.return_value.raise_for_status.return_value = None

    runner = CliRunner()
    result = runner.invoke(registry, ["pull", "--vc-id", "123", "--raw"])

    assert result.exit_code == 0
    assert result.output.strip() == raw_json


def test_pull_from_vdr_to_file(mocker, tmp_path):
    """Test `registry pull` to a file."""
    mock_get = mocker.patch("httpx.get")
    mock_get.return_value.status_code = 200
    vc_json = json.dumps(SIGNED_VC)
    mock_get.return_value.text = vc_json
    mock_get.return_value.raise_for_status.return_value = None

    runner = CliRunner()
    output_file = tmp_path / "vc.json"
    result = runner.invoke(
        registry, ["pull", "--vc-id", "123", "--output", str(output_file)]
    )

    assert result.exit_code == 0
    assert f"VC saved to {output_file}" in result.output
    assert output_file.read_text() == vc_json


def test_pull_from_vdr_http_error(mocker):
    """Test `registry pull` with an HTTP error."""
    mock_response = mocker.MagicMock()
    mock_response.status_code = 404
    mock_response.text = '{"detail":"Not Found"}'
    mock_response.json.return_value = {"detail": "Not Found"}

    mock_get = mocker.patch("httpx.get")
    mock_get.side_effect = httpx.HTTPStatusError(
        "Not Found", request=mocker.MagicMock(), response=mock_response
    )

    runner = CliRunner()
    result = runner.invoke(registry, ["pull", "--vc-id", "123"])

    # This assertion is tricky because the exception is constructed with a message
    # and the request object, so we check the output message instead.
    assert "Failed to fetch VC" in result.output
    assert "Details: Not Found" in result.output


def test_pull_from_vdr_mutually_exclusive_flags(mocker):
    """Test `registry pull` with --raw and --pretty."""
    runner = CliRunner()
    result = runner.invoke(registry, ["pull", "--vc-id", "123", "--raw", "--pretty"])
    assert result.exit_code == 0
    assert "Error: --raw and --pretty are mutually exclusive" in result.output 