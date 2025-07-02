import json
from typing import Optional

import click
from akta.did import DIDKey, DIDWeb

from akta.utils import prepare_issuer_key_file_data


@click.group("keys")
def keys():
    """Create and manage keys for DID Documents and Verifiable Credentials"""
    pass


@keys.command("create-key")
@click.option(
    "-o",
    "--output",
    "output_file",
    type=click.Path(dir_okay=False, writable=True),
    help="Output file for the DID key information (JSON).",
)
def create_did_key(output_file: Optional[str]):
    """Generates a new did:key and saves its information in JSON format."""
    did_instance = DIDKey()  # Now uses multibase internally
    click.echo(click.style(f"Generated DID: {did_instance.did}", fg="cyan"))

    # The verification method for did:key LDPs is typically the DID itself, or DID#publicKeyMultibase
    # Using DID#publicKeyMultibase is more explicit for Ed25519Signature2020
    verification_method_ldp = f"{did_instance.did}#{did_instance.public_key_multibase}"
    click.echo(
        click.style(
            f"Verification Method (for LDP): {verification_method_ldp}", fg="yellow"
        )
    )

    key_data_to_save = did_instance.to_dict()
    # Ensure it matches the expected IssuerKeyFileModel structure if used as such
    # We want the output file to be usable as an --issuer-key-file for vc sign
    output_for_issuer_key_file = prepare_issuer_key_file_data(
        key_data_to_save, verification_method_ldp
    )

    if output_file:
        with open(output_file, "w") as f:
            json.dump(output_for_issuer_key_file, f, indent=2)
        click.echo(
            click.style(
                f"DID key information saved in JSON format to {output_file}", fg="green"
            )
        )
    else:
        click.echo(json.dumps(output_for_issuer_key_file, indent=2))


@keys.command("create-web")
@click.option("--domain", "-d", required=True, help="Domain name for the did:web.")
@click.option(
    "--path", "-p", help="Optional path segments for the did:web, comma-separated."
)
@click.option(
    "--output-did-document",
    type=click.Path(dir_okay=False, writable=True),
    help="Output file for the DID Document (did.json).",
)
@click.option(
    "--output-keys",
    type=click.Path(dir_okay=False, writable=True),
    help="Output file for the DID's keys (JSON with multibase format).",
)
def create_did_web(domain, path, output_did_document, output_keys):
    """Generates a new did:web, its DID Document, and key information."""
    path_list = path.split(",") if path else []
    did_web_instance = DIDWeb(domain=domain, path=path_list)  # Now uses multibase internally

    click.echo(click.style(f"Generated DID: {did_web_instance.did}", fg="cyan"))
    click.echo(
        click.style(
            f"Verification Method (for LDP in DID Document): {did_web_instance.key_id}",
            fg="yellow",
        )
    )

    click.echo("\nDID Document:")
    click.echo(json.dumps(did_web_instance.did_document, indent=2))

    if output_did_document:
        with open(output_did_document, "w") as f:
            json.dump(did_web_instance.did_document, f, indent=2)
        click.echo(
            click.style(f"DID Document saved to {output_did_document}", fg="green")
        )
        # Construct the URL based on how DIDWeb class forms the DID for path resolution
        # The DID itself: did:web:example.com or did:web:example.com:some:path
        did_path_part = did_web_instance.did.replace(f"did:web:{domain}", "")
        if did_path_part.startswith(":"):
            did_path_part = did_path_part[1:]
        url_path_segments = did_path_part.replace(":", "/")

        if not url_path_segments:  # Root DID for domain
            did_doc_url = f"https://{domain}/.well-known/did.json"
        else:
            did_doc_url = f"https://{domain}/{url_path_segments}/did.json"
        click.echo(f"Ensure this document is accessible at: {did_doc_url}")

    if output_keys:
        # did_web_instance.to_dict() now returns multibase keys and key_id
        keys_data_to_save = did_web_instance.to_dict()
        # Ensure it matches IssuerKeyFileModel for consistency if used as --issuer-key-file
        output_for_issuer_key_file = prepare_issuer_key_file_data(
            keys_data_to_save, keys_data_to_save.get("key_id")
        )
        with open(output_keys, "w") as f:
            json.dump(output_for_issuer_key_file, f, indent=2)
        click.echo(
            click.style(f"Key information (multibase) saved to {output_keys}", fg="green")
        ) 