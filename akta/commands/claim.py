import fnmatch
import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

import base58
import click
import httpx
from pyakta.credentials import VerifiableCredential
from pyakta.did import resolve_verification_key
from pydantic import ValidationError

from akta.a2a.models import AgentCard
from akta.utils import (
    get_certificate_details,
    load_signing_key_from_file,
    load_vc_from_file,
    save_unsigned_vc,
)


@click.group("claim")
def claim():
    """Create and manage Verifiable Credentials using Linked Data Proofs (LDP)."""
    pass


@claim.command("fetch-agentcard")
@click.option("--url", required=True, help="URL of the agent card.")
@click.option(
    "--tls-fingerprint",
    is_flag=True,
    help="Capture TLS Fingerprint and certificate details.",
)
@click.option(
    "--issuer-did", required=True, help="Issuer's DID for the AgentSkillAccess VC."
)
@click.option(
    "--subject-did",
    required=True,
    help="Subject's DID for the AgentSkillAccess VC (who is granted access).",
)
@click.option(
    "--usage-limit", type=int, help="Set a usageLimit for each granted skill."
)
@click.option(
    "--can-delegate", is_flag=True, help="Set canDelegate=true for each granted skill."
)
@click.option("--expiration-days", type=int, help="Number of days until the VC expires.")
@click.option(
    "--output",
    "-o",
    "output_path",
    type=click.Path(dir_okay=False, writable=True),
    required=True,
    help="Output file for the generated AgentSkillAccess VC (JSON).",
)
@click.option(
    "--vc-id",
    "credential_id",
    help="Custom ID for the Verifiable Credential (defaults to urn:uuid:...).",
)
def fetch_a2a(
    url: str,
    tls_fingerprint: bool,
    issuer_did: str,
    subject_did: str,
    usage_limit: Optional[int],
    can_delegate: bool,
    expiration_days: Optional[int],
    output_path: str,
    credential_id: Optional[str],
):
    """Fetches an agent card, validates it, and generates an AgentSkillAccess Verifiable Credential granting all skills found in the card."""
    click.echo(click.style("\nFetching Agent Card and Generating VC", bold=True))
    click.echo("=" * 50)

    ## see if url is non-https
    if not url.startswith("https://") and tls_fingerprint:
        click.echo(
            click.style(
                "Warning: The URL is not HTTPS. This is not recommended for production.",
                fg="yellow",
            )
        )
        click.echo(
            click.style(
                "         TLS evidence cannot be collected and will be skipped.",
                fg="yellow",
            )
        )
        tls_fingerprint = False

    try:
        click.echo(f"-> Fetching agent card from: {click.style(url, fg='cyan')}")
        response = httpx.get(url)
        response.raise_for_status()
        agent_card_data = response.json()
        click.echo(click.style("Successfully fetched agent card data.", fg="green"))
    except httpx.RequestError as e:
        click.echo(
            click.style(f"Error fetching agent card from {url}: {e}", fg="red"),
            err=True,
        )
        return
    except httpx.HTTPStatusError as e:
        click.echo(
            click.style(
                f"Error fetching agent card: {e.response.status_code} - {e.response.text}",
                fg="red",
            ),
            err=True,
        )
        return
    except json.JSONDecodeError as e:
        click.echo(
            click.style(f"Error decoding JSON from agent card response: {e}", fg="red"),
            err=True,
        )
        return
    except Exception as e:
        click.echo(
            click.style(
                f"An unexpected error occurred while fetching agent card: {e}", fg="red"
            ),
            err=True,
        )
        return

    click.echo("\n" + "=" * 50)
    click.echo(click.style("Validating Agent Card", bold=True))
    click.echo("=" * 50)

    try:
        # Validate the fetched data against the AgentCard Pydantic model
        validated_agent_card = AgentCard.model_validate(agent_card_data)
        click.echo(
            click.style(
                "Agent card data validated against the A2A AgentCard protocol.",
                fg="green",
            )
        )

        click.echo(click.style("\n--- Agent Details ---", bold=True))
        click.echo(f'  {click.style("Name:", fg="blue"):<15} {validated_agent_card.name}')
        click.echo(
            f'  {click.style("Description:", fg="blue"):<15} {validated_agent_card.description}'
        )
        click.echo(f'  {click.style("URL:", fg="blue"):<15} {validated_agent_card.url}')

        if validated_agent_card.skills:
            click.echo(f'  {click.style("Skills:", fg="blue")}')
            for i in validated_agent_card.skills:
                click.echo(f'    - {click.style("Name:", fg="cyan"):<15} {i.name}')
                click.echo(
                    f'      {click.style("Description:", fg="cyan"):<15} {i.description}'
                )
                if i.tags:
                    click.echo(
                        f'      {click.style("Tags:", fg="cyan"):<15} {", ".join(i.tags)}'
                    )
        click.echo(click.style("---------------------\n", bold=True))

    except ValidationError as e:
        click.echo(
            click.style(
                "\nAgent card data does not match the AgentCard schema:", fg="red"
            ),
            err=True,
        )
        click.echo(click.style(str(e), fg="red"), err=True)
        return  # Stop further processing if validation fails

    if tls_fingerprint:
        click.echo("=" * 50)
        click.echo(click.style("Verifying TLS Certificate Evidence", bold=True))
        click.echo("=" * 50)
        certificate_details = get_certificate_details(url)
        if certificate_details is None:
            click.echo(
                click.style(
                    "TLS certificate details not found. Strict pinning failed.", fg="red"
                ),
                err=True,
            )
            return

        # The common_name check should be against the hostname of the URL where the cert was obtained.
        # so we grab it for now
        expected_hostname = urlparse(url).hostname

        cn_match = certificate_details["common_name"] == expected_hostname
        san_match = False
        if not cn_match and "subject_alt_names" in certificate_details:
            for san_dns_name in certificate_details["subject_alt_names"]:
                if fnmatch.fnmatch(expected_hostname, san_dns_name):
                    san_match = True
                    break

        if not cn_match and not san_match:
            click.echo(
                click.style(
                    f"TLS certificate common name or SAN does not match hostname: CN='{certificate_details['common_name']}', SANs='{certificate_details.get('subject_alt_names', [])}' != '{expected_hostname}'",
                    fg="red",
                ),
                err=True,
            )
            return

        try:
            cert_valid_from_str = certificate_details.get("valid_from")
            cert_valid_to_str = certificate_details.get("valid_to")

            if cert_valid_from_str == "N/A" or cert_valid_to_str == "N/A":
                click.echo(
                    click.style(
                        "TLS certificate validity dates are not available.", fg="red"
                    ),
                    err=True,
                )
                return

            dt_format = "%b %d %H:%M:%S %Y"
            parsed_valid_from = datetime.strptime(
                cert_valid_from_str.replace(" GMT", ""), dt_format
            )
            parsed_valid_to = datetime.strptime(
                cert_valid_to_str.replace(" GMT", ""), dt_format
            )

            valid_from_dt = parsed_valid_from.replace(tzinfo=UTC)
            valid_to_dt = parsed_valid_to.replace(tzinfo=UTC)

        except ValueError as e:
            click.echo(
                click.style(
                    f"Error parsing certificate validity dates: {e}. Dates: From='{cert_valid_from_str}', To='{cert_valid_to_str}'",
                    fg="red",
                ),
                err=True,
            )
            return

        now_utc = datetime.now(UTC)
        if valid_from_dt > now_utc:
            click.echo(
                click.style(
                    f"TLS certificate is not yet valid: {valid_from_dt} > {now_utc}",
                    fg="red",
                ),
                err=True,
            )
            return
        if valid_to_dt < now_utc:
            click.echo(
                click.style(
                    f"TLS certificate has expired: {valid_to_dt} < {now_utc}", fg="red"
                ),
                err=True,
            )
            return

        click.echo(click.style("TLS Certificate is valid.", fg="green"))
        click.echo(
            f'  {click.style("Common Name:", fg="blue"):<20} {certificate_details.get("common_name")}'
        )
        click.echo(
            f'  {click.style("Thumbprint SHA256:", fg="blue"):<20} {certificate_details.get("thumb_sha256")}\n'
        )

    click.echo("=" * 50)
    click.echo(click.style("Generating Verifiable Credential", bold=True))
    click.echo("=" * 50)

    # Construct unsigned VC from the Agent Card
    vc_builder = VerifiableCredential()

    # 1. Prepare Agent Card Hash for evidence
    try:
        agent_card_json_bytes = json.dumps(
            agent_card_data, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        digest = hashlib.sha256(agent_card_json_bytes).digest()
        # SHA2-256 multihash prefix: 0x12 (sha2-256), 0x20 (32 bytes length)
        multihash_bytes = bytes([0x12, 0x20]) + digest
        # Base58btc encode the multihash bytes (typically starts with 'Qm' for SHA256)
        agent_card_hash = base58.b58encode(multihash_bytes).decode("ascii")
    except Exception as e:
        click.echo(
            click.style(f"Error generating hash for agent card: {e}", fg="red"),
            err=True,
        )
        return

    evidence_payload = [
        {
            "id": url,  # URL of the agent card
            "type": "AgentCardSnapshot",
            "description": "AgentCard used for this issuance",
            "hash": agent_card_hash,
        }
    ]

    # Add TLS certificate details to evidence if strict pinning was enabled and details were fetched
    if (
        tls_fingerprint
        and "certificate_details" in locals()
        and certificate_details
    ):  # certificate_details would have been populated above
        tls_evidence_entry = {
            "type": "TlsCertificateSnapshot",
            "retrievedFromUrl": url,
            "commonName": certificate_details.get("common_name"),
            "subjectAlternativeNames": certificate_details.get("subject_alt_names"),
            "validFrom": certificate_details.get("valid_from"),
            "validTo": certificate_details.get("valid_to"),
            "serialNumber": certificate_details.get("serial_number"),
            "thumbprintSha256": certificate_details.get("thumb_sha256"),
        }
        # Filter out any None values from the entry to keep evidence clean
        tls_evidence_entry = {k: v for k, v in tls_evidence_entry.items() if v is not None}
        if (
            tls_evidence_entry.get("thumbprintSha256")
        ):  # Only add if we have the crucial thumbprint
            evidence_payload.append(tls_evidence_entry)
        else:
            click.echo(
                click.style(
                    "Warning: TLS certificate thumbprint was missing, not adding TLS details to evidence.",
                    fg="yellow",
                )
            )

    # 2. Prepare credentialSubject.skills by iterating through all skills in the agent card
    skills_for_cs = []
    if not validated_agent_card.skills:
        click.echo(
            click.style("Warning: The fetched agent card has no skills defined.", fg="yellow")
        )
    else:
        for skill_from_card in validated_agent_card.skills:
            skill_id = getattr(skill_from_card, "id", None)
            if not skill_id:
                click.echo(
                    click.style(
                        f"Warning: Skipping a skill from agent card because it has no 'id'. Skill details: {skill_from_card.model_dump(mode='json', exclude_none=True)}",
                        fg="yellow",
                    )
                )
                continue

            # Use the skill's tags as the scope. Ensure tags is a list.
            skill_scope = []
            if hasattr(skill_from_card, "tags") and skill_from_card.tags is not None:
                if isinstance(skill_from_card.tags, list):
                    skill_scope = skill_from_card.tags
                else:
                    click.echo(
                        click.style(
                            f"Warning: Tags for skill '{skill_id}' is not a list, attempting to use as single scope item: {skill_from_card.tags}",
                            fg="yellow",
                        )
                    )
                    skill_scope = [str(skill_from_card.tags)]

            skill_entry: Dict[str, Any] = {
                "id": skill_id,
                "granted": True,
                "scope": skill_scope,
            }

            # Add usageLimit to the skill entry if provided
            if usage_limit is not None:
                skill_entry["usageLimit"] = usage_limit

            # Add canDelegate to the skill entry if flag is true
            if can_delegate:
                skill_entry["canDelegate"] = True

            skills_for_cs.append(skill_entry)

    # 3. Prepare full credentialSubject
    credential_subject_payload: Dict[str, Any] = {
        "id": subject_did,
        "skills": skills_for_cs,
    }

    click.echo(click.style("\n--- Credential Subject ---", bold=True))
    click.echo(json.dumps(credential_subject_payload, indent=2))
    click.echo(click.style("--------------------------\n", bold=True))

    click.echo(click.style("--- Evidence ---", bold=True))
    click.echo(json.dumps(evidence_payload, indent=2))
    click.echo(click.style("----------------\n", bold=True))

    # 5. VC ID and Dates
    final_credential_id = credential_id or f"urn:uuid:{uuid.uuid4()}"
    expiration_date_obj: Optional[datetime] = None
    if expiration_days:
        expiration_date_obj = datetime.now(UTC) + timedelta(days=expiration_days)

    # 6. VC Types and Contexts (using defaults from your example)
    vc_types = ["VerifiableCredential", "AgentSkillAccess"]
    vc_contexts = [
        "https://www.w3.org/2018/credentials/v1",
        "https://w3id.org/security/suites/ed25519-2020/v1"
        # Potentially add a specific context for AgentSkillAccess if defined
    ]

    try:
        vc_builder.build(
            issuer_did=issuer_did,
            subject_did=None,  # Handled inside credential_subject_payload.id
            credential_id=final_credential_id,
            types=vc_types,
            contexts=vc_contexts,
            issuance_date=datetime.now(UTC),
            expiration_date=expiration_date_obj,
            credential_subject=credential_subject_payload,
        )

        # Directly assign evidence to the model if the model and payload exist
        if vc_builder.model and evidence_payload:
            vc_builder.model.evidence = evidence_payload

    except ValidationError as e:
        click.echo(
            click.style(
                f"Error creating AgentSkillAccess VC due to validation issues: {e}",
                fg="red",
            ),
            err=True,
        )
        return
    except Exception as e:
        click.echo(
            click.style(f"Error building AgentSkillAccess VC: {e}", fg="red"), err=True
        )
        return
    save_unsigned_vc(vc_builder, output_path, "AgentSkillAccess VC created and")


@claim.command("draft")
@click.option(
    "--method",
    type=click.Choice(["key", "web"], case_sensitive=False),
    required=True,
    help="Method to use for the draft (e.g., did:key:z... or did:web:example.com).",
)
@click.option(
    "--issuer-did",
    required=True,
    help="Issuer's DID (e.g., did:key:z... or did:web:example.com).",
)
@click.option("--subject-did", required=True, help="Subject's DID.")
@click.option(
    "--credential-subject",
    "credential_subject_path",
    type=click.Path(exists=True, dir_okay=False, readable=True),
    help="Path to a JSON file containing the credentialSubject data.",
)
@click.option(
    "--agent-card",
    "agent_card_path",
    type=click.Path(exists=True, dir_okay=False, readable=True),
    help="Path to a JSON file containing agent card data.",
)
@click.option("--expiration-days", type=int, help="Number of days until the VC expires.")
@click.option(
    "--output",
    "-o",
    type=click.Path(dir_okay=False, writable=True),
    required=True,
    help="Output file for the unsigned VC (JSON).",
)
@click.option("--id", "credential_id", help="Custom ID for the Verifiable Credential.")
@click.option(
    "--type", "types", multiple=True, help="VC Type (can be specified multiple times)."
)
@click.option(
    "--context",
    "contexts_str",
    multiple=True,
    help="VC @context URI or JSON string (can be specified multiple times).",
)
def draft_vc(
    method,
    issuer_did,
    subject_did,
    credential_subject_path,
    agent_card_path,
    expiration_days,
    output,
    credential_id,
    types,
    contexts_str,
):
    """Drafts a Verifiable Credential."""
    if credential_subject_path and agent_card_path:
        click.echo(
            click.style(
                "Error: --credential-subject and --agent-card are mutually exclusive.",
                fg="red",
            ),
            err=True,
        )
        return

    vc_builder = VerifiableCredential()

    cred_subject_data: Dict[str, Any]
    if credential_subject_path:
        try:
            with open(credential_subject_path, "r") as f:
                cred_subject_data = json.load(f)
        except json.JSONDecodeError as e:
            click.echo(
                click.style(
                    f"Error: Invalid JSON in credential subject file {credential_subject_path}: {e}",
                    fg="red",
                ),
                err=True,
            )
            return
        except Exception as e:
            click.echo(
                click.style(
                    f"Error reading credential subject file {credential_subject_path}: {e}",
                    fg="red",
                ),
                err=True,
            )
            return
    elif agent_card_path:
        try:
            with open(agent_card_path, "r") as f:
                agent_card_data = json.load(f)
            validated_agent_card = AgentCard.model_validate(agent_card_data)
            cred_subject_data = {
                "id": subject_did,
                "skills": [
                    skill.model_dump() for skill in validated_agent_card.skills
                ],
            }
            if not types:
                types = ("VerifiableCredential", "AgentSkillAccess")

        except json.JSONDecodeError as e:
            click.echo(
                click.style(
                    f"Error: Invalid JSON in agent card file {agent_card_path}: {e}",
                    fg="red",
                ),
                err=True,
            )
            return
        except ValidationError as e:
            click.echo(
                click.style(
                    f"Agent card data in {agent_card_path} does not match the AgentCard schema: {e}",
                    fg="red",
                ),
                err=True,
            )
            return
        except Exception as e:
            click.echo(
                click.style(
                    f"Error reading agent card file {agent_card_path}: {e}",
                    fg="red",
                ),
                err=True,
            )
            return
    else:
        cred_subject_data = {"id": subject_did}

    expiration_date_obj: Optional[datetime] = None
    if expiration_days:
        expiration_date_obj = datetime.now(UTC) + timedelta(days=expiration_days)

    vc_types_list = list(types) if types else None

    parsed_contexts: Optional[List[Union[str, Dict]]] = None
    if contexts_str:
        parsed_contexts = []
        for c_str in contexts_str:
            try:
                # Attempt to parse as JSON dict if it starts with {
                if c_str.strip().startswith("{"):
                    parsed_contexts.append(json.loads(c_str))
                else:
                    parsed_contexts.append(c_str)  # Assume URI string
            except json.JSONDecodeError:
                click.echo(
                    click.style(
                        f"Warning: Could not parse context '{c_str}' as JSON, treating as string URI.",
                        fg="yellow",
                    )
                )
                parsed_contexts.append(c_str)

    try:
        vc_builder.build(
            issuer_did=issuer_did,
            subject_did=subject_did,
            credential_id=credential_id,
            types=vc_types_list,
            contexts=parsed_contexts,  # Pass parsed contexts
            issuance_date=datetime.now(UTC),
            expiration_date=expiration_date_obj,
            credential_subject=cred_subject_data,
        )
    except ValidationError as e:
        click.echo(
            click.style(f"Error creating VC due to validation issues: {e}", fg="red"),
            err=True,
        )
        return
    except Exception as e:
        click.echo(click.style(f"Error building VC: {e}", fg="red"), err=True)
        return
    save_unsigned_vc(vc_builder, output, "Unsigned LDP VC created and")


@claim.command("sign")
@click.option(
    "--vc-file",
    type=click.Path(exists=True, dir_okay=False, readable=True),
    required=True,
    help="Path to the unsigned VC JSON file.",
)
@click.option(
    "--issuer-key-file",
    type=click.Path(exists=True, dir_okay=False, readable=True),
    required=True,
    help="Path to the issuer's key file (JSON, with privateKeyMultibase).",
)
@click.option(
    "--verification-method",
    required=True,
    help="Verification method ID (e.g., did:example:123#key-1 or did:key:z...#z...). This must match a key in the issuer's DID doc or be the did:key itself.",
)
@click.option(
    "--output",
    "-o",
    "output_path",
    type=click.Path(dir_okay=False, writable=True),
    required=True,
    help="Output file for the signed VC (JSON with LDP proof).",
)
@click.option(
    "--proof-purpose",
    default="assertionMethod",
    show_default=True,
    help="Proof purpose for the LDP signature.",
)
def sign_vc(
    vc_file: str,
    issuer_key_file: str,
    verification_method: str,
    output_path: str,
    proof_purpose: str,
):
    """Signs a Verifiable Credential."""
    unsigned_vc = load_vc_from_file(vc_file)
    if not unsigned_vc:
        return

    try:
        signing_key = load_signing_key_from_file(issuer_key_file)
        if not signing_key:
            return

        signed_vc = unsigned_vc.sign(
            issuer_signing_key=signing_key,
            verification_method_id=verification_method,
            proof_purpose=proof_purpose,
        )

        with open(output_path, "w") as f:
            f.write(signed_vc.to_json(indent=2))
        click.echo(
            click.style(f"VC signed with LDP and saved to {output_path}", fg="green")
        )

    except Exception as e:
        click.echo(click.style(f"Error signing VC: {e}", fg="red"), err=True)


@claim.command("verify")
@click.option(
    "--vc-file",
    type=click.Path(exists=True, dir_okay=False, readable=True),
    required=True,
    help="Path to the signed VC JSON file (LDP).",
)
@click.option(
    "--did-web-scheme",
    default="https",
    show_default=True,
    type=click.Choice(["http", "https"]),
    help="Scheme to use for did:web resolution.",
)
@click.option(
    "--issuer-did",
    help="Expected issuer DID (e.g., did:key:z... or did:web:example.com). If provided, this can help resolve the key, especially if the VC proof's verificationMethod is relative or needs context.",
)
def verify_vc(vc_file, did_web_scheme, issuer_did):
    """Verifies a Verifiable Credential."""
    vc_to_verify = load_vc_from_file(vc_file)
    if not vc_to_verify:
        return

    try:
        if (
            not vc_to_verify.model
            or not vc_to_verify.model.proof
            or not vc_to_verify.model.proof.verificationMethod
        ):
            click.echo(
                click.style("❌ VC is missing proof or verificationMethod in proof.", fg="red"),
                err=True,
            )
            return

        verification_method_url_from_proof = (
            vc_to_verify.model.proof.verificationMethod
        )

        issuer_vkey = resolve_verification_key(
            verification_method_url=verification_method_url_from_proof,
            issuer_did_hint=issuer_did,
            did_web_scheme=did_web_scheme,
        )

        if not issuer_vkey:
            click.echo(
                click.style("Could not obtain issuer public key for verification.", fg="red"),
                err=True,
            )
            return

        is_valid = vc_to_verify.verify_signature(issuer_vkey)

        if is_valid:
            click.echo(click.style("VC Signature is VALID.", fg="green"))
        else:
            # verify_signature method in VerifiableCredential prints detailed errors
            click.echo(click.style("VC Signature is INVALID.", fg="red"))

    except Exception as e:
        click.echo(click.style(f"Error verifying VC: {e}", fg="red"), err=True) 