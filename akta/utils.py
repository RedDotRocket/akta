import hashlib
import json
import logging
import socket
import ssl
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import base58
import click
from nacl.signing import SigningKey, VerifyKey
from pyakta.credentials import VerifiableCredential
from pyakta.models import IssuerKeyFileModel
from pydantic import ValidationError

logger = logging.getLogger(__name__)


def prepare_issuer_key_file_data(did_data: dict, verification_method: str) -> dict:
    """Prepares the dictionary for an issuer key file from DID data."""
    return {
        "did": did_data.get("did"),
        "publicKeyMultibase": did_data.get("publicKeyMultibase"),
        "privateKeyMultibase": did_data.get("privateKeyMultibase"),
        "verificationMethod": verification_method
    }

def load_vc_from_file(vc_file_path: str) -> Optional[VerifiableCredential]:
    """Loads a Verifiable Credential from a JSON file."""
    try:
        with open(vc_file_path, 'r') as f:
            vc_data = json.load(f)
        return VerifiableCredential.from_dict(vc_data)
    except FileNotFoundError:
        click.echo(click.style(f"Error: VC file {vc_file_path} not found.", fg="red"), err=True)
        return None
    except json.JSONDecodeError as e:
        click.echo(click.style(f"Error: Invalid JSON in VC file {vc_file_path}: {e}", fg="red"), err=True)
        return None
    except ValidationError as e:
        click.echo(click.style(f"Error validating VC data from {vc_file_path}: {e}", fg="red"), err=True)
        return None
    except Exception as e: # Catch-all for other unexpected errors during load/parse
        click.echo(click.style(f"Unexpected error loading VC from {vc_file_path}: {e}", fg="red"), err=True)
        return None

def load_signing_key_from_file(key_file_path: str) -> Optional[SigningKey]:
    """Loads a signing key from an issuer key JSON file."""
    try:
        with open(key_file_path, 'r') as f:
            key_data_from_file = json.load(f)

        issuer_key_model = IssuerKeyFileModel(**key_data_from_file)

        if not issuer_key_model.privateKeyMultibase:
            click.echo(click.style(f"Error: privateKeyMultibase not found in {key_file_path}.", fg="red"), err=True)
            return None

        seed_bytes = base58.b58decode(issuer_key_model.privateKeyMultibase)
        return SigningKey(seed_bytes)

    except FileNotFoundError:
        click.echo(click.style(f"Error: Issuer key file {key_file_path} not found.", fg="red"), err=True)
        return None
    except json.JSONDecodeError as e:
        click.echo(click.style(f"Error: Invalid JSON in issuer key file {key_file_path}: {e}", fg="red"), err=True)
        return None
    except ValidationError as e:
        click.echo(click.style(f"Error: Issuer key file {key_file_path} is invalid or missing privateKeyMultibase: {e}", fg="red"), err=True)
        return None
    except Exception as e:
        click.echo(click.style(f"Error initializing signing key from {key_file_path}: {e}", fg="red"), err=True)
        return None

def save_unsigned_vc(vc_builder: VerifiableCredential, output_path: str, success_message_stem: str):
    """Saves an unsigned Verifiable Credential to a JSON file."""
    if vc_builder.model:
        try:
            # Serialize using Pydantic's model_dump_json for better control (e.g., exclude_none)
            # vc_json_output = vc_builder.model.model_dump_json(indent=2, exclude_none=True)
            # For consistency with existing .to_json() which might be used elsewhere or have specific settings:
            vc_json_output = vc_builder.to_json(indent=2) # Assuming .to_json() is preferred for VerifiableCredential instances

            # If model_dump_json is preferred for exclude_none=True behavior, switch to:
            # vc_json_output = vc_builder.model.model_dump_json(indent=2, exclude_none=True)

            with open(output_path, 'w') as f:
                f.write(vc_json_output)
            click.echo(click.style(f"{success_message_stem} saved to {output_path}", fg="green"))
            click.echo(click.style("This VC is unsigned. Use 'akta claim sign' to sign it.", fg="yellow"))
        except Exception as e:
            click.echo(click.style(f"Error serializing or saving VC to {output_path}: {e}", fg="red"), err=True)
    else:
        click.echo(click.style("Error: VC model was not available for saving.", fg="red"), err=True)


def get_certificate_details(addr: str) -> Optional[Dict[str, Any]]:
    try:
        parsed_url = urlparse(addr)
        hostname = parsed_url.hostname
        if not hostname:
            logger.error(f"Could not extract hostname from URL: {addr}")
            return None
    except Exception as e:
        logger.error(f"Error parsing URL {addr}: {e}")
        return None

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)

    wrappedSocket = None
    try:
        wrappedSocket = context.wrap_socket(sock, server_hostname=hostname)
        wrappedSocket.connect((hostname, 443))
    except socket.gaierror as e:
        logger.error(f"Could not connect to {hostname} (address error): {e}")
        return None
    except socket.timeout:
        logger.error(f"Connection to {hostname} timed out.")
        return None
    except ssl.SSLCertVerificationError as e:
        logger.error(f"SSL certificate verification error for {hostname}: {e}")
        return None
    except ConnectionRefusedError:
        logger.error(f"Connection refused by {hostname}.")
        return None
    except Exception as e:
        logger.error(f"Could not connect to {hostname} or SSL error: {e}")
        return None
    else:
        der_cert_bin = wrappedSocket.getpeercert(True)
        cert_dict = wrappedSocket.getpeercert()

        if der_cert_bin is None or cert_dict is None:
            logger.error("Could not retrieve complete certificate information (DER binary or dictionary is missing).")
            return None

        try:
            thumb_sha256 = hashlib.sha256(der_cert_bin).hexdigest()
        except Exception as e:
            logger.error(f"Error processing DER certificate binary (for thumbprint): {e}")
            return None

        subject_info = cert_dict.get('subject')
        common_name = 'N/A'
        if subject_info:
            try:
                subject = dict(x[0] for x in subject_info)
                common_name = subject.get('commonName', 'N/A')
            except (TypeError, IndexError):
                common_name = 'N/A'

        valid_from = cert_dict.get('notBefore', 'N/A')
        valid_to = cert_dict.get('notAfter', 'N/A')
        serial_number = cert_dict.get('serialNumber', 'N/A')

        subject_alt_names = []
        if 'subjectAltName' in cert_dict:
            for type, value in cert_dict['subjectAltName']:
                if type == 'DNS':
                    subject_alt_names.append(value)

        return {
            "common_name": common_name,
            "valid_from": valid_from,
            "valid_to": valid_to,
            "serial_number": serial_number,
            "thumb_sha256": thumb_sha256,
            "subject_alt_names": subject_alt_names,
        }
    finally:
        if wrappedSocket:
            wrappedSocket.close()

def get_verify_key_from_multibase(pk_multibase: str) -> VerifyKey:
    """Decodes a base58check-encoded Ed25519 public key (multibase 'z' prefix)
    and returns a PyNaCl VerifyKey object.
    Handles common multicodec prefixes for Ed25519 public keys.
    """
    if not pk_multibase:
        raise ValueError("Public key multibase string cannot be empty.")
    if not pk_multibase.startswith('z'):
        raise ValueError(f"Ed25519 publicKeyMultibase '{pk_multibase}' must start with 'z'.")

    multicodec_pubkey = base58.b58decode(pk_multibase[1:]) # Skip 'z'

    # Check for typical Ed25519 multicodec prefixes
    # 0xed01 for full 34-byte key (prefix + key)
    # 0xed for 33-byte key (prefix + key, less common for this representation but check)
    if multicodec_pubkey.startswith(bytes([0xed, 0x01])) and len(multicodec_pubkey) == 34:
        public_key_bytes = multicodec_pubkey[2:]
    elif multicodec_pubkey.startswith(bytes([0xed])) and len(multicodec_pubkey) == 33: # Check for 0xed prefix if key is 32 bytes + 1 prefix byte
        public_key_bytes = multicodec_pubkey[1:]
    elif len(multicodec_pubkey) == 32: # Assume raw 32-byte key if no recognized prefix and correct length
        public_key_bytes = multicodec_pubkey
    else:
        raise ValueError(f"Invalid Ed25519 multicodec prefix or key length in publicKeyMultibase '{pk_multibase}'. Decoded length: {len(multicodec_pubkey)} bytes.")

    if len(public_key_bytes) != 32:
        raise ValueError(f"Final public key bytes length is not 32 for Ed25519. Got {len(public_key_bytes)} from '{pk_multibase}'.")

    return VerifyKey(public_key_bytes)