import json
from unittest.mock import MagicMock, patch
from click.testing import CliRunner
from akta.commands.claim import claim
import httpx

AGENT_CARD = {
  "name": "Quote Agent",
  "description": "This agent will give you a random quote",
  "capabilities": {},
  "defaultInputModes": [
    "text"
  ],
  "defaultOutputModes": [
    "text"
  ],
  "provider": {
    "organization": "John Doe",
    "url": "https://example.com"
  },
  "skills": [
    {
      "description": "just returns hello world",
      "examples": [
        "hi",
        "hello world"
      ],
      "id": "hello_world",
      "name": "Returns hello world",
      "tags": [
        "hello world"
      ]
    },
    {
      "description": "Returns a random quote",
      "examples": [
        "quote"
      ],
      "id": "quote",
      "name": "Returns a random quote",
      "tags": [
        "quote"
      ]
    },
    {
      "description": "Returns the weather",
      "examples": [
        "weather"
      ],
      "id": "weather",
      "name": "Returns the weather",
      "tags": [
        "weather"
      ]
    }
  ],
  "url": "https://example.com/.well-known/agent.json4",
  "version": "1.0.0"
}


@patch("akta.a2a.models.AgentCard")
def test_fetch_agentcard_success(mock_agent_card, mocker, tmp_path):
    """Test `claim fetch-agentcard` successful case."""
    mock_agent_card.model_validate.return_value = MagicMock(skills=[MagicMock(name="read")])
    mock_get = mocker.patch("httpx.get")
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = AGENT_CARD
    mock_get.return_value.raise_for_status.return_value = None

    runner = CliRunner()
    output_file = tmp_path / "vc.json"
    result = runner.invoke(
        claim,
        [
            "fetch-agentcard",
            "--url",
            "https://example.com/agent",
            "--issuer-did",
            "did:key:issuer",
            "--subject-did",
            "did:key:subject",
            "--output",
            str(output_file),
        ],
    )

    assert result.exit_code == 0
    assert "Successfully fetched agent card data." in result.output
    assert "Agent card data validated against the A2A AgentCard protocol." in result.output
    assert output_file.exists()

    with open(output_file, "r") as f:
        vc_data = json.load(f)

    assert vc_data["issuer"] == "did:key:issuer"
    assert vc_data["credentialSubject"]["id"] == "did:key:subject"
    assert vc_data["credentialSubject"]["skills"][0]["id"] == "hello_world"


@patch("akta.a2a.models.AgentCard")
@patch("akta.commands.claim.get_certificate_details")
def test_fetch_agentcard_with_tls(mock_get_cert_details, mock_agent_card, mocker, tmp_path):
    """Test `claim fetch-agentcard` with TLS fingerprinting."""
    mock_agent_card.model_validate.return_value = MagicMock(skills=[MagicMock(name="read")])
    mock_get = mocker.patch("httpx.get")
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = AGENT_CARD
    mock_get.return_value.raise_for_status.return_value = None

    mock_get_cert_details.return_value = {
        "common_name": "example.com",
        "valid_from": "Jan 01 00:00:00 2023 GMT",
        "valid_to": "Jan 01 00:00:00 2035 GMT",
        "thumb_sha256": "fingerprint",
        "subject_alt_names": ["example.com"],
    }

    runner = CliRunner()
    output_file = tmp_path / "vc.json"
    result = runner.invoke(
        claim,
        [
            "fetch-agentcard",
            "--url",
            "https://example.com/agent",
            "--tls-fingerprint",
            "--issuer-did",
            "did:key:issuer",
            "--subject-did",
            "did:key:subject",
            "--output",
            str(output_file),
        ],
    )

    assert result.exit_code == 0
    assert "TLS Certificate is valid" in result.output
    assert output_file.exists()


def test_fetch_agentcard_http_error(mocker, tmp_path):
    """Test `claim fetch-agentcard` with an HTTP error."""
    mock_get = mocker.patch("httpx.get")
    mock_get.side_effect = httpx.RequestError("Connection error", request=mocker.MagicMock())

    runner = CliRunner()
    output_file = tmp_path / "vc.json"
    result = runner.invoke(
        claim,
        [
            "fetch-agentcard",
            "--url",
            "https://example.com/agent",
            "--issuer-did",
            "did:key:issuer",
            "--subject-did",
            "did:key:subject",
            "--output",
            str(output_file),
        ],
    )

    assert result.exit_code == 0
    assert "Error fetching agent card from https://example.com/agent: Connection error" in result.output


@patch("akta.a2a.models.AgentCard")
@patch("akta.commands.claim.get_certificate_details")
def test_fetch_agentcard_tls_cn_mismatch(mock_get_cert_details, mock_agent_card, mocker, tmp_path):
    """Test `claim fetch-agentcard` with TLS CN mismatch."""
    mock_agent_card.model_validate.return_value = MagicMock(skills=[MagicMock(name="read")])
    mock_get = mocker.patch("httpx.get")
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = AGENT_CARD
    mock_get.return_value.raise_for_status.return_value = None

    mock_get_cert_details.return_value = {
        "common_name": "wrong.com",
        "valid_from": "Jan 01 00:00:00 2023 GMT",
        "valid_to": "Jan 01 00:00:00 2025 GMT",
        "thumb_sha256": "fingerprint",
        "subject_alt_names": ["another.com"],
    }

    runner = CliRunner()
    output_file = tmp_path / "vc.json"
    result = runner.invoke(
        claim,
        [
            "fetch-agentcard",
            "--url",
            "https://example.com/agent",
            "--tls-fingerprint",
            "--issuer-did",
            "did:key:issuer",
            "--subject-did",
            "did:key:subject",
            "--output",
            str(output_file),
        ],
    )
    assert result.exit_code == 0
    assert "TLS certificate common name or SAN does not match hostname" in result.output


def test_draft_vc_with_credential_subject(tmp_path):
    """Test `claim draft` with a credential subject file."""
    runner = CliRunner()
    cs_file = tmp_path / "cs.json"
    cs_data = {"id": "did:key:subject", "alumniOf": "Example University"}
    cs_file.write_text(json.dumps(cs_data))
    output_file = tmp_path / "vc.json"

    result = runner.invoke(
        claim,
        [
            "draft",
            "--method",
            "key",
            "--issuer-did",
            "did:key:issuer",
            "--subject-did",
            "did:key:subject",
            "--credential-subject",
            str(cs_file),
            "--output",
            str(output_file),
        ],
    )

    assert result.exit_code == 0
    assert "Unsigned LDP VC created and saved" in result.output
    assert output_file.exists()
    with open(output_file, "r") as f:
        vc = json.load(f)
    assert vc["credentialSubject"]["alumniOf"] == "Example University"
    assert vc["credentialSubject"]["id"] == "did:key:subject"


def test_draft_vc_with_agent_card(tmp_path):
    """Test `claim draft` with an agent card file."""
    runner = CliRunner()
    card_file = tmp_path / "card.json"
    card_file.write_text(json.dumps(AGENT_CARD))
    output_file = tmp_path / "vc.json"

    result = runner.invoke(
        claim,
        [
            "draft",
            "--method",
            "key",
            "--issuer-did",
            "did:key:issuer",
            "--subject-did",
            "did:key:subject",
            "--agent-card",
            str(card_file),
            "--output",
            str(output_file),
        ],
    )

    assert result.exit_code == 0
    assert output_file.exists()
    with open(output_file, "r") as f:
        vc = json.load(f)
    assert vc["credentialSubject"]["id"] == "did:key:subject"
    assert vc["credentialSubject"]["skills"][0]["id"] == "hello_world"


def test_draft_vc_mutual_exclusion(tmp_path):
    """Test `claim draft` fails with both --credential-subject and --agent-card."""
    runner = CliRunner()
    cs_file = tmp_path / "cs.json"
    cs_file.write_text("{}")
    card_file = tmp_path / "card.json"
    card_file.write_text("{}")
    output_file = tmp_path / "vc.json"

    result = runner.invoke(
        claim,
        [
            "draft",
            "--method",
            "key",
            "--issuer-did",
            "did:key:issuer",
            "--subject-did",
            "did:key:subject",
            "--credential-subject",
            str(cs_file),
            "--agent-card",
            str(card_file),
            "--output",
            str(output_file),
        ],
    )

    assert result.exit_code == 0
    assert "Error: --credential-subject and --agent-card are mutually exclusive" in result.output

@patch("akta.utils.load_signing_key_from_file")
@patch("akta.utils.VerifiableCredential")
def test_sign_vc_success(mock_vc, mock_load_key, mocker, tmp_path):
    """Test `claim sign` successful case."""
    mock_vc_instance = MagicMock()
    signed_vc_instance = MagicMock()
    signed_vc_instance.to_json.return_value = '{"signed": true}'
    mock_vc_instance.sign.return_value = signed_vc_instance
    mock_vc.from_dict.return_value = mock_vc_instance

    mock_load_key.return_value = MagicMock()  # Return a dummy key object

    runner = CliRunner()
    vc_file = tmp_path / "unsigned.json"
    unsigned_vc_data = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "id": "http://example.edu/credentials/1872",
        "type": ["VerifiableCredential", "AlumniCredential"],
        "issuer": "did:key:issuer",
        "issuanceDate": "2010-01-01T19:23:24Z",
        "credentialSubject": {"id": "did:example:123"},
    }
    vc_file.write_text(json.dumps(unsigned_vc_data))
    key_file = tmp_path / "key.json"
    key_content = """{
  "did": "did:key:z6MkknvqHdiEyATcTfDobPVqWn8rXjy8rhb7dBqmHj1WeRqC",
  "publicKeyMultibase": "z6MkknvqHdiEyATcTfDobPVqWn8rXjy8rhb7dBqmHj1WeRqC",
  "privateKeyMultibase": "8JRqARoB2BUCkBc72M7xmAzLSgfpHHHeSW2SctQ5c2h8",
  "verificationMethod": "did:key:z6MkknvqHdiEyATcTfDobPVqWn8rXjy8rhb7dBqmHj1WeRqC#z6MkknvqHdiEyATcTfDobPVqWn8rXjy8rhb7dBqmHj1WeRqC"
}"""
    key_file.write_text(key_content)
    output_file = tmp_path / "signed.json"

    result = runner.invoke(
        claim,
        [
            "sign",
            "--vc-file",
            str(vc_file),
            "--issuer-key-file",
            str(key_file),
            "--verification-method",
            "did:key:issuer#key-1",
            "--output",
            str(output_file),
        ],
    )

    # Assert
    assert result.exit_code == 0
    assert "VC signed with LDP and saved" in result.output
    assert output_file.exists()
    assert output_file.read_text() == '{"signed": true}'
    mock_vc_instance.sign.assert_called_once()


def test_sign_vc_no_key_file(tmp_path):
    """Test `claim sign` with a non-existent key file."""
    runner = CliRunner()
    vc_file = tmp_path / "unsigned.json"
    vc_file.write_text('{"issuer": "did:key:issuer"}')
    output_file = tmp_path / "signed.json"

    result = runner.invoke(
        claim,
        [
            "sign",
            "--vc-file",
            str(vc_file),
            "--issuer-key-file",
            "nonexistent.json",
            "--verification-method",
            "did:key:issuer#key-1",
            "--output",
            str(output_file),
        ],
    )

    assert result.exit_code != 0
    assert "Invalid value for '--issuer-key-file'" in result.output

@patch("akta.utils.VerifiableCredential")
@patch("akta.commands.claim.resolve_verification_key")
def test_verify_vc_success(mock_resolve_key, mock_vc, mocker, tmp_path):
    """Test `claim verify` successful case."""
    mock_resolve_key.return_value = MagicMock()  # Return a dummy key object

    mock_vc_instance = MagicMock()
    mock_vc_instance.proof = MagicMock() # Ensure proof attribute exists

    mock_vc.from_dict.return_value = mock_vc_instance

    runner = CliRunner()
    vc_file = tmp_path / "signed.json"
    signed_vc_data = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "id": "http://example.edu/credentials/1872",
        "type": ["VerifiableCredential", "AlumniCredential"],
        "issuer": "did:key:issuer",
        "issuanceDate": "2010-01-01T19:23:24Z",
        "credentialSubject": {"id": "did:example:123"},
        "proof": {"verificationMethod": "did:key:issuer#key-1"},
    }
    vc_file.write_text(json.dumps(signed_vc_data))

    result = runner.invoke(claim, ["verify", "--vc-file", str(vc_file)])

    assert result.exit_code == 0
    assert "VC Signature is VALID" in result.output

def test_verify_vc_no_file():
    """Test `claim verify` with a non-existent VC file."""
    runner = CliRunner()
    result = runner.invoke(claim, ["verify", "--vc-file", "nonexistent.json"])

    assert result.exit_code != 0
    assert "Invalid value for '--vc-file'" in result.output