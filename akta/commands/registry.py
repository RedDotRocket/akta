import json
from typing import Optional

import click
import httpx

from akta.config import settings


@click.group("registry")
def registry():
    """Manage Verifiable Credentials in a Verifiable Data Registry"""
    pass


@registry.command("push")
@click.option(
    "--vc-file",
    "vc_file_path",
    type=click.Path(exists=True, dir_okay=False, readable=True),
    required=True,
    help="Path to the signed Verifiable Credential JSON file.",
)
@click.option(
    "--vdr-url",
    default=f"http://{settings.host}:{settings.port}/api/v1/",
    show_default=True,
    help="Base URL of the VC Store API.",
)
def push_to_vdr(vc_file_path: str, vdr_url: str):
    """Pushes a signed VC to the VDR."""
    try:
        with open(vc_file_path, "r") as f:
            vc_data = json.load(f)

        if (
            vc_data.get("proof", {}).get("proofValue")
            and not vc_data.get("proof", {}).get("jws")
        ):
            click.echo(
                click.style(
                    "Warning: Publishing VC with LDP proof. The VC store might not fully support LDP verification/querying yet.",
                    fg="yellow",
                )
            )

        api_endpoint = f"{vdr_url.rstrip('/')}/vdr"
        click.echo(f"Attempting to publish VC from {vc_file_path} to {api_endpoint}...")

        # The VC store endpoint expects the VC to be nested under "verifiable_credential" key
        payload_to_send = {"verifiable_credential": vc_data}

        response = httpx.post(
            api_endpoint, json=payload_to_send
        )  # Send the structured payload

        click.echo(f"Response Status Code: {response.status_code}")
        try:
            response_body = response.json()
            click.echo("Response Body: " + json.dumps(response_body, indent=2))
            if response.is_success and response_body.get("status") == "success":
                click.echo(click.style("VC published successfully!", fg="green"))
            elif response.is_success:
                click.echo(
                    click.style(
                        f"VC publish action completed with server message: {response_body.get('message', 'No message.')}",
                        fg="yellow",
                    )
                )
            else:
                click.echo(
                    click.style(
                        f"Failed to publish VC: {response_body.get('detail', 'No details provided.')}",
                        fg="red",
                    )
                )
        except json.JSONDecodeError:
            click.echo(
                click.style(f"Could not decode JSON response: {response.text}", fg="red")
            )

    except FileNotFoundError:
        click.echo(
            click.style(f"Error: VC file {vc_file_path} not found.", fg="red"), err=True
        )
    except json.JSONDecodeError as e:
        click.echo(
            click.style(
                f"Error: Invalid JSON in VC file {vc_file_path}: {e}", fg="red"
            ),
            err=True,
        )
    except httpx.RequestError as e:
        click.echo(
            click.style(f"HTTP request error while publishing VC: {e}", fg="red"),
            err=True,
        )
    except Exception as e:
        click.echo(
            click.style(f"An unexpected error occurred: {e}", fg="red"), err=True
        )


@registry.command("pull")
@click.option(
    "--vdr-url",
    default=f"http://{settings.host}:{settings.port}/api/v1/",
    show_default=True,
    help="Base URL of the VDR API.",
)
@click.option(
    "--vc-id",
    required=True,
    help="ID of the VC to get, sometimes the urn:uuid:... part of the VC's id.",
)
@click.option(
    "--output",
    "-o",
    "output_file",
    type=click.Path(dir_okay=False, writable=True),
    help="Save the fetched VC to a file.",
)
@click.option("--raw", is_flag=True, help="Print raw JSON output to stdout.")
@click.option(
    "--pretty",
    is_flag=True,
    help="Print pretty-formatted JSON to stdout. This is the default if no other output option is specified.",
)
def pull_from_vdr(
    vdr_url: str, vc_id: str, output_file: Optional[str], raw: bool, pretty: bool
):
    """Pulls a VC from the VDR."""
    if raw and pretty:
        click.echo(
            click.style("Error: --raw and --pretty are mutually exclusive.", fg="red"),
            err=True,
        )
        return

    # Default to pretty print if no other output-related flags are provided
    if not output_file and not raw and not pretty:
        pretty = True

    api_endpoint = f"{vdr_url.rstrip('/')}/vdr/{vc_id}"

    try:
        response = httpx.get(api_endpoint)
        response.raise_for_status()

        # At this point, request was successful
        vc_json_text = response.text

        if output_file:
            with open(output_file, "w") as f:
                f.write(vc_json_text)
            click.echo(click.style(f"VC saved to {output_file}", fg="green"))

        if pretty:
            try:
                vc_data = json.loads(vc_json_text)
                click.echo(json.dumps(vc_data, indent=2))
            except json.JSONDecodeError:
                click.echo(
                    click.style(
                        "Successfully fetched response, but it was not valid JSON for pretty printing:",
                        fg="yellow",
                    )
                )
                click.echo(vc_json_text)  # Fallback to raw output
        elif raw:
            click.echo(vc_json_text)

    except httpx.HTTPStatusError as e:
        message = f"Failed to fetch VC: HTTP {e.response.status_code}."
        try:
            # Append server's error message if available and is valid JSON
            error_detail = e.response.json().get("detail", e.response.text)
            message += f"\nDetails: {error_detail}"
        except json.JSONDecodeError:
            message += f"\nResponse: {e.response.text}"
        click.echo(click.style(message, fg="red"), err=True)
    except httpx.RequestError as e:
        click.echo(
            click.style(
                f"Request error while fetching VC from {api_endpoint}: {e}", fg="red"
            ),
            err=True,
        )
    except Exception as e:
        click.echo(
            click.style(f"An unexpected error occurred: {e}", fg="red"), err=True
        ) 