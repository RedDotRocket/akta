import json
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from akta.commands.keys import keys


@patch("akta.commands.keys.DIDKey")
def test_create_did_key_no_output(mock_did_key):
    """Test `keys create-key` without an output file."""
    # Arrange
    mock_instance = MagicMock()
    mock_instance.did = "did:key:z6Mkt"
    mock_instance.public_key_multibase = "z6Mkt..."
    mock_instance.to_dict.return_value = {
        "did": "did:key:z6Mkt",
        "publicKeyMultibase": "z6Mkt...",
        "privateKeyMultibase": "z...",
    }
    mock_did_key.return_value = mock_instance

    runner = CliRunner()

    # Act
    result = runner.invoke(keys, ["create-key"])

    # Assert
    assert result.exit_code == 0
    assert "Generated DID: did:key:z6Mkt" in result.output
    assert "Verification Method (for LDP): did:key:z6Mkt#z6Mkt..." in result.output
    json_output_str = result.output[result.output.find("{") :]
    output_json = json.loads(json_output_str)
    assert output_json["did"] == "did:key:z6Mkt"
    assert output_json["verificationMethod"] == "did:key:z6Mkt#z6Mkt..."


@patch("akta.commands.keys.DIDKey")
def test_create_did_key_with_output_file(mock_did_key, tmp_path):
    """Test `keys create-key` with an output file."""
    # Arrange
    mock_instance = MagicMock()
    mock_instance.did = "did:key:z6Mkt"
    mock_instance.public_key_multibase = "z6Mkt..."
    mock_instance.to_dict.return_value = {
        "did": "did:key:z6Mkt",
        "publicKeyMultibase": "z6Mkt...",
        "privateKeyMultibase": "z...",
    }
    mock_did_key.return_value = mock_instance

    output_file = tmp_path / "did_key.json"
    runner = CliRunner()

    # Act
    result = runner.invoke(keys, ["create-key", "--output", str(output_file)])

    # Assert
    assert result.exit_code == 0
    assert f"DID key information saved in JSON format to {output_file}" in result.output
    assert output_file.exists()

    with open(output_file, "r") as f:
        data = json.load(f)
    assert data["did"] == "did:key:z6Mkt"
    assert data["verificationMethod"] == "did:key:z6Mkt#z6Mkt..."


@patch("akta.commands.keys.DIDWeb")
def test_create_did_web_no_output(mock_did_web):
    """Test `keys create-web` without output files."""
    # Arrange
    mock_instance = MagicMock()
    mock_instance.did = "did:web:example.com"
    mock_instance.key_id = "did:web:example.com#key-1"
    mock_instance.did_document = {
        "id": "did:web:example.com",
        "controller": "did:web:example.com",
    }
    mock_did_web.return_value = mock_instance

    runner = CliRunner()

    # Act
    result = runner.invoke(keys, ["create-web", "--domain", "example.com"])

    # Assert
    assert result.exit_code == 0
    assert "Generated DID: did:web:example.com" in result.output
    assert "DID Document:" in result.output
    assert '"id": "did:web:example.com"' in result.output


@patch("akta.commands.keys.DIDWeb")
def test_create_did_web_with_output_files(mock_did_web, tmp_path):
    """Test `keys create-web` with output files."""
    # Arrange
    mock_instance = MagicMock()
    mock_instance.did = "did:web:example.com:users:1234"
    mock_instance.key_id = "did:web:example.com:users:1234#key-1"
    mock_instance.did_document = {"id": "did:web:example.com:users:1234"}
    mock_instance.to_dict.return_value = {
        "did": "did:web:example.com:users:1234",
        "key_id": "did:web:example.com:users:1234#key-1",
        "publicKeyMultibase": "z...",
        "privateKeyMultibase": "z...",
    }
    mock_did_web.return_value = mock_instance

    did_doc_file = tmp_path / "did.json"
    keys_file = tmp_path / "keys.json"
    runner = CliRunner()

    # Act
    result = runner.invoke(
        keys,
        [
            "create-web",
            "--domain",
            "example.com",
            "--path",
            "users,1234",
            "--output-did-document",
            str(did_doc_file),
            "--output-keys",
            str(keys_file),
        ],
    )

    # Assert
    assert result.exit_code == 0
    assert f"DID Document saved to {did_doc_file}" in result.output
    assert f"Key information (multibase) saved to {keys_file}" in result.output
    assert did_doc_file.exists()
    assert keys_file.exists()

    with open(did_doc_file, "r") as f:
        did_doc = json.load(f)
    assert did_doc["id"] == "did:web:example.com:users:1234"

    with open(keys_file, "r") as f:
        keys_data = json.load(f)
    assert keys_data["did"] == "did:web:example.com:users:1234"
    assert keys_data["verificationMethod"] == "did:web:example.com:users:1234#key-1" 