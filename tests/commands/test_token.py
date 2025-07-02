import json
import base64
from click.testing import CliRunner
from akta.commands.token import token
from akta.models import VerifiableCredentialModel

SIGNED_VC = {
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1",
    ],
    "id": "http://example.edu/credentials/3732",
    "type": ["VerifiableCredential", "UniversityDegreeCredential"],
    "issuer": "https://example.edu/issuers/14",
    "issuanceDate": "2010-01-01T19:23:24Z",
    "credentialSubject": {
        "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "degree": {"type": "BachelorDegree", "name": "Baccalauréat en musiques numériques"},
    },
    "proof": {
        "type": "Ed25519Signature2020",
        "created": "2023-11-20T14:46:17Z",
        "verificationMethod": "did:key:z6MksH3e4Y2x8g2dX4iCRn59yG7hMDSf3p29bA2sSSRg3Pti#z6MksH3e4Y2x8g2dX4iCRn59yG7hMDSf3p29bA2sSSRg3Pti",
        "proofPurpose": "assertionMethod",
        "proofValue": "z24DAMq...p9oYg",
    },
}

UNSIGNED_VC = {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "id": "http://example.edu/credentials/1872",
    "type": ["VerifiableCredential", "AlumniCredential"],
    "issuer": "https://example.edu/issuers/14",
    "issuanceDate": "2010-01-01T19:23:24Z",
    "credentialSubject": {"id": "did:example:123"},
}


def test_generate_token_unsigned_vc(tmp_path):
    """Test token generate with an unsigned VC."""
    runner = CliRunner()
    vc_file = tmp_path / "unsigned_vc.json"
    vc_file.write_text(json.dumps(UNSIGNED_VC))

    result = runner.invoke(token, ["generate", "--vc-file", str(vc_file)])

    assert result.exit_code == 0 # The command itself doesn't exit with 1, it just prints to stderr
    assert "Error: The provided VC is not signed." in result.output


def test_generate_token_stdout(tmp_path):
    """Test token generate with a signed VC, printing raw token to stdout."""
    runner = CliRunner()
    vc_file = tmp_path / "signed_vc.json"
    vc_file.write_text(json.dumps(SIGNED_VC))

    result = runner.invoke(token, ["generate", "--vc-file", str(vc_file), "--raw-token"])

    assert result.exit_code == 0
    # With --raw-token, only the token should be printed.
    # The output will have a newline, so we strip it.
    token_from_output = result.output.strip()

    # The token generation uses Pydantic's `model_dump_json` for compact serialization.
    # We must replicate this to get the correct expected token.
    vc_model = VerifiableCredentialModel.model_validate(SIGNED_VC)
    vc_compact_json = vc_model.model_dump_json(exclude_none=True)
    expected_token = base64.b64encode(vc_compact_json.encode("utf-8")).decode("ascii")

    assert token_from_output == expected_token


def test_generate_token_file_output(tmp_path):
    """Test token generate with a signed VC, writing to a file."""
    runner = CliRunner()
    vc_file = tmp_path / "signed_vc.json"
    vc_file.write_text(json.dumps(SIGNED_VC))
    token_file = tmp_path / "token.txt"

    result = runner.invoke(
        token, ["generate", "--vc-file", str(vc_file), "--token-file", str(token_file)]
    )

    assert result.exit_code == 0
    assert f"Bearer Token saved to {token_file}" in result.output
    assert token_file.exists()

    from akta.models import VerifiableCredentialModel
    vc_model = VerifiableCredentialModel.model_validate(SIGNED_VC)
    vc_compact_json = vc_model.model_dump_json(exclude_none=True)
    expected_token_from_model = base64.b64encode(vc_compact_json.encode("utf-8")).decode("ascii")

    assert token_file.read_text() == expected_token_from_model