import base64
import json
from typing import Optional

import click

from akta.utils import load_vc_from_file


@click.group("token")
def token():
    """Generate or verify Bearer Tokens from signed VC"""
    pass


@token.command("generate")
@click.option(
    "--vc-file",
    "vc_file_path",
    type=click.Path(exists=True, dir_okay=False, readable=True),
    required=True,
    help="Path to the signed Verifiable Credential JSON file.",
)
@click.option(
    "--token-file",
    "token_file_path",
    type=click.Path(dir_okay=False, writable=True),
    help="Path to save the generated Bearer Token.",
)
def generate_token(vc_file_path: str, token_file_path: Optional[str]):
    """Generates a Bearer Token from a signed VC."""
    vc = load_vc_from_file(vc_file_path)
    if not vc:
        return

    # A signed VC must have a proof section.
    if not vc.model or not vc.model.proof:
        click.echo(
            click.style(
                "Error: The provided VC is not signed. A 'proof' section is required to generate a Bearer Token.",
                fg="red",
            ),
            err=True,
        )
        return

    try:
        # To match `jq -c`, we produce compact JSON. model_dump_json from Pydantic does this.
        vc_compact_json = vc.model.model_dump_json(exclude_none=True)
        if not vc_compact_json:
            click.echo(
                click.style("Error: Failed to serialize VC to JSON.", fg="red"), err=True
            )
            return

        # The user's shell command `base64 -b0` on macOS avoids line wrapping.
        # Python's b64encode does not add newlines, so this is equivalent.
        token = base64.b64encode(vc_compact_json.encode("utf-8")).decode("ascii")

        if token_file_path:
            with open(token_file_path, "w") as f:
                f.write(token)
            click.echo(
                click.style(f"Bearer Token saved to {token_file_path}", fg="green")
            )
        else:
            click.echo("Generated Bearer Token:")
            click.echo(click.style(token, fg="cyan"))

        click.echo("\nTo use this token, include it in the Authorization header:")
        click.echo(click.style("Authorization: Bearer <token>", fg="yellow"))

    except Exception as e:
        click.echo(
            click.style(
                f"An unexpected error occurred during token generation: {e}", fg="red"
            ),
            err=True,
        ) 