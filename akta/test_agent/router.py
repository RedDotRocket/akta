import base64
import json
import logging
from datetime import UTC, datetime
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from nacl.signing import VerifyKey
from akta.credentials import VerifiableCredential
from akta.models import (
    CredentialSubjectWithSkillsModel,
    DIDDocumentModel,
    MapGenerationParams,
    MapGenerationResponse,
    VerifiableCredentialModel,
)
from pydantic import ValidationError

from a2a.types import (
    AgentCard,
    AgentCapabilities,
    AgentSkill,
    AgentProvider,
)

from akta.config import settings
from akta.utils import get_verify_key_from_multibase

logger = logging.getLogger(__name__)


async def _resolve_did_key_verification_method(verification_method_url: str) -> VerifyKey:
    """Resolves a 'did:key' verification method URL to a PyNaCl VerifyKey."""
    fragment_identifier = verification_method_url.split('#')[-1]
    if not fragment_identifier.startswith('z'):
        raise ValueError(f"did:key verification method fragment {fragment_identifier} does not look like a multibase key.")
    return get_verify_key_from_multibase(fragment_identifier)

async def _construct_did_web_url(did_web_identifier: str) -> str:
    """Constructs the DID document URL from a 'did:web' identifier string (post 'did:web:' prefix)."""
    parts = did_web_identifier.split(':')
    host_plus_port = parts[0]
    path_start_index = 1

    # Handle port in DID identifier, e.g., did:web:localhost:8000
    if ':' not in parts[0] and len(parts) > 1 and parts[1].isdigit():
        host_plus_port = f"{parts[0]}:{parts[1]}"
        path_start_index = 2

    path_segments = parts[path_start_index:]
    # Ensure path segments are URL-decoded if necessary, though current example seems fine
    url_path_part = "/".join(segment for segment in path_segments if segment)

    scheme = "http" if host_plus_port.startswith("localhost") or host_plus_port.startswith("127.0.0.1") else "https"

    if not url_path_part:
        return f"{scheme}://{host_plus_port}/.well-known/did.json"
    else:
        # For did:web:example.com:path:to:did, results in https://example.com/path/to/did/did.json
        return f"{scheme}://{host_plus_port}/{url_path_part}/did.json"

async def _resolve_did_web_verification_method(verification_method_url: str, did_doc_url: str) -> VerifyKey:
    """Resolves a 'did:web' verification method using a fetched DID document."""
    async with httpx.AsyncClient() as client:
        response = await client.get(did_doc_url, timeout=10.0)
        response.raise_for_status() # Handled by the main try-except in _resolve_verification_key
        did_doc_data = response.json()
        did_doc = DIDDocumentModel(**did_doc_data) # Handled by the main try-except

    found_vm = None
    for vm in did_doc.verificationMethod:
        if vm.id == verification_method_url:
            found_vm = vm
            break

    if not found_vm or not found_vm.publicKeyMultibase:
        raise ValueError(f"Verification method {verification_method_url} not found or no publicKeyMultibase in DID document {did_doc_url}.")
    return get_verify_key_from_multibase(found_vm.publicKeyMultibase)

async def _resolve_verification_key(verification_method_url: str) -> VerifyKey:
    """Resolves a verification method URL to a PyNaCl VerifyKey."""
    try:
        if verification_method_url.startswith("did:key:"):
            return await _resolve_did_key_verification_method(verification_method_url)

        elif verification_method_url.startswith("did:web:"):
            did_string_no_fragment = verification_method_url.split('#')[0]
            identifier_after_prefix = did_string_no_fragment[len("did:web:"):]

            did_doc_url = await _construct_did_web_url(identifier_after_prefix)
            logger.info(f"INFO: Attempting to fetch DID Document from: {did_doc_url}")

            return await _resolve_did_web_verification_method(verification_method_url, did_doc_url)
        else:
            raise ValueError(f"Unsupported DID method in verificationMethod: {verification_method_url}")
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error resolving {verification_method_url}: {e.response.status_code} - {e.response.text}")
        raise HTTPException(status_code=502, detail=f"Error resolving DID document for {verification_method_url}: upstream error.")
    except httpx.RequestError as e:
        logger.error(f"Request error resolving {verification_method_url}: {e}")
        raise HTTPException(status_code=503, detail=f"Could not connect to resolve DID for {verification_method_url}.")
    except (json.JSONDecodeError, ValidationError, ValueError) as e:
        logger.error(f"Error parsing or validating data for {verification_method_url}: {e}")
        raise HTTPException(status_code=500, detail=f"Invalid data encountered during DID resolution for {verification_method_url}.")
    except Exception as e:
        logger.error(f"Unexpected error resolving {verification_method_url}: {type(e).__name__} - {e}")
        raise HTTPException(status_code=500, detail=f"Unexpected error resolving verification key for {verification_method_url}.")

# Placeholder for revocation check - remains the same
def is_revoked(vc_id: str) -> bool:
    logger.info(f"Checking revocation for VC ID: {vc_id} (currently always returns False - placeholder)")
    return False

def parse_datetime_utc(date_str: str) -> datetime:
    try:
        if date_str.endswith("Z"):
            dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        else:
            dt = datetime.fromisoformat(date_str)
        return dt.astimezone(UTC)
    except ValueError as e:
        raise ValueError(f"Could not parse date string: {date_str}. Error: {e}")

async def verify_single_ldp_vc(vc: VerifiableCredential) -> bool:
    """Verifies a single LDP VC's signature. Does not handle delegation chain."""
    if not vc.model or not vc.model.proof or not vc.model.proof.verificationMethod:
        # This should ideally be caught earlier by Pydantic model validation or initial checks
        logger.warning("VC model, proof, or verificationMethod missing in verify_single_ldp_vc")
        return False

    verification_method_url = vc.model.proof.verificationMethod
    try:
        issuer_verify_key = await _resolve_verification_key(verification_method_url)
        if not vc.verify_signature(issuer_verify_key):
            # vc.verify_signature() prints detailed errors
            return False
    except HTTPException as e:
        logger.error(f"HTTPException during single LDP VC signature verification for {vc.id if vc else 'Unknown VC'}: {e.detail}")
        raise
    except Exception as e:
        logger.error(f"Error during single LDP VC signature verification for {vc.id if vc else 'Unknown VC'}: {type(e).__name__} - {e}")
        return False
    return True

async def get_verified_vc_from_auth(authorization: Optional[str] = Header(None)) -> VerifiableCredential:
    """
    FastAPI dependency to verify a Verifiable Credential (LDP) from Authorization Bearer token.
    Handles signature verification and basic checks (revocation, expiration).
    Does NOT handle the delegation chain here; that's done by the calling function if needed.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Invalid or missing Bearer token.")

    token = authorization.split(" ", 1)[1]
    try:
        # Re-add padding if necessary for base64.urlsafe_b64decode
        # urlsafe_b64decode expects padding, but our shell script removed it.
        missing_padding = len(token) % 4
        if missing_padding:
            token += '=' * (4 - missing_padding)

        vc_json_str = base64.urlsafe_b64decode(token.encode('utf-8')).decode('utf-8')
        vc_instance = VerifiableCredential.from_json(vc_json_str)
    except (base64.binascii.Error, UnicodeDecodeError, json.JSONDecodeError, ValidationError) as e:
        # Include the specific error type in the detail for better debugging
        error_type_name = type(e).__name__
        raise HTTPException(status_code=401, detail=f"Invalid LDP VC token format or content: {error_type_name} - {e}")
    except Exception as e: # Catch-all for unexpected errors during initial parsing
        error_type_name = type(e).__name__
        raise HTTPException(status_code=400, detail=f"Could not process LDP VC token: {error_type_name} - {e}")

    if not vc_instance.model or not vc_instance.model.proof or not vc_instance.model.proof.verificationMethod:
        raise HTTPException(status_code=400, detail="Presented VC is malformed or missing proof details.")

    # Verify the signature of the presented VC
    if not await verify_single_ldp_vc(vc_instance):
        # verify_single_ldp_vc and vc.verify_signature print detailed errors
        raise HTTPException(status_code=403, detail="Presented VC signature verification failed.")

    # Basic checks on the presented VC
    if not vc_instance.id:
        raise HTTPException(status_code=400, detail="Presented VC is missing an 'id' field.")
    if is_revoked(vc_instance.id):
        raise HTTPException(status_code=403, detail="Presented VC has been revoked.")

    if vc_instance.expiration_date:
        exp_date = vc_instance.expiration_date # Property access is timezone-aware
        if datetime.now(UTC) > exp_date:
            raise HTTPException(status_code=403, detail="Presented VC has expired.")
    # else: Consider policy on VCs missing expirationDate
    #     logger.warning(f"Presented VC {vc_instance.id} missing 'expirationDate'. Policy might reject this.")

    return vc_instance

async def _fetch_and_verify_parent_vc(parent_vc_id_ref: str, vc_store_base_url: str) -> VerifiableCredential:
    """Fetches, parses, and verifies a parent VC (signature, expiration, revocation)."""
    parent_vc: Optional[VerifiableCredential] = None
    try:
        logger.info(f"Retrieving parent VC {parent_vc_id_ref} from VC store: {vc_store_base_url}/{parent_vc_id_ref}")
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{vc_store_base_url}/{parent_vc_id_ref}")
            response.raise_for_status()
            parent_vc_data = response.json()
            parent_vc = VerifiableCredential.from_dict(parent_vc_data)
    except httpx.HTTPStatusError as e:
        # Log original error for server-side details
        logger.error(f"HTTPStatusError while fetching parent VC {parent_vc_id_ref}: {e.response.status_code} - {e.response.text}")
        raise HTTPException(status_code=e.response.status_code, detail=f"Error retrieving parent VC {parent_vc_id_ref} from VC Store.")
    except (json.JSONDecodeError, ValidationError) as e:
        logger.error(f"Parsing/Validation error for parent VC {parent_vc_id_ref}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to parse or validate parent VC {parent_vc_id_ref} from VC Store.")
    except httpx.RequestError as e:
        logger.error(f"RequestError while fetching parent VC {parent_vc_id_ref}: {e}")
        raise HTTPException(status_code=503, detail=f"Could not connect to VC Store to retrieve parent VC {parent_vc_id_ref}.")

    if not parent_vc or not parent_vc.model:
        # This case should ideally be covered by the above, but as a safeguard:
        logger.error(f"Parent VC {parent_vc_id_ref} model not loaded successfully.")
        raise HTTPException(status_code=500, detail=f"Failed to obtain parent VC {parent_vc_id_ref} model after retrieval.")

    # Verify the signature of the parent VC
    if not await verify_single_ldp_vc(parent_vc):
        # verify_single_ldp_vc prints details
        raise HTTPException(status_code=403, detail=f"Parent VC (ID: {parent_vc.id}) signature verification failed. Delegation chain broken.")
    logger.info(f"Parent VC {parent_vc.id} signature verified.")

    # Check parent VC expiration and revocation
    if parent_vc.expiration_date and datetime.now(UTC) > parent_vc.expiration_date:
        raise HTTPException(status_code=403, detail=f"Parent VC (ID: {parent_vc.id}) has expired. Delegation invalid.")
    if is_revoked(parent_vc.id):
        # is_revoked prints details
        raise HTTPException(status_code=403, detail=f"Parent VC (ID: {parent_vc.id}) has been revoked. Delegation invalid.")

    return parent_vc

async def _validate_delegation_rules(presented_vc: VerifiableCredential, current_cs_model: CredentialSubjectWithSkillsModel):
    """Validates the delegation rules specified in the presented VC's credentialSubject."""
    logger.info(f"Validating delegation rules for presented VC {presented_vc.id}")
    if not current_cs_model.delegationDetails:
        # This indicates it's not a delegated VC, or details are missing.
        # The calling function should handle this (e.g., return presented_vc as is).
        return # Or raise a specific error if delegationDetails are strictly expected at this point by caller

    logger.info(f"Presented VC {presented_vc.id} is a delegated VC. Performing delegation rules validation.")
    parent_vc_id_ref = current_cs_model.delegationDetails.get("parentVC")
    delegated_by_did = current_cs_model.delegationDetails.get("delegatedBy")
    delegation_valid_until_str = current_cs_model.delegationDetails.get("validUntil")

    if not all([parent_vc_id_ref, delegated_by_did, delegation_valid_until_str]):
        raise HTTPException(status_code=400, detail="Delegated VC missing required delegationDetails (parentVC, delegatedBy, validUntil).")

    if presented_vc.issuer_did != delegated_by_did:
        logger.error(f"Delegation fraud: Issuer of delegated VC ({presented_vc.issuer_did}) does not match delegationDetails.delegatedBy ({delegated_by_did}).")
        raise HTTPException(status_code=403, detail=f"Delegation fraud: Issuer of delegated VC ({presented_vc.issuer_did}) does not match delegationDetails.delegatedBy ({delegated_by_did}).")

    try:
        delegation_exp_date = parse_datetime_utc(delegation_valid_until_str)
        if datetime.now(UTC) > delegation_exp_date:
            logger.error(f"Delegation itself has expired as of {delegation_exp_date.isoformat()}.")
            raise HTTPException(status_code=403, detail=f"Delegation itself has expired as of {delegation_exp_date.isoformat()}.")
    except ValueError as e: # Catches errors from parse_datetime_utc
        raise HTTPException(status_code=400, detail=f"Invalid validUntil format in delegationDetails: {e}")

    # Return key details if needed by caller, though side-effects (exceptions) are primary
    return parent_vc_id_ref

async def _check_parent_delegation_permission(parent_vc: VerifiableCredential, presented_vc_issuer_did: str):
    """Checks if the parent VC permits delegation to the issuer of the presented VC."""
    logger.info(f"Checking parent VC {parent_vc.id} for delegation permission to {presented_vc_issuer_did}")
    if parent_vc.subject_did != presented_vc_issuer_did:
        logger.error(f"Delegation chain broken: Subject of parent VC ({parent_vc.subject_did}) does not match issuer of delegated VC ({presented_vc_issuer_did}).")
        raise HTTPException(status_code=403, detail=f"Delegation chain broken: Subject of parent VC ({parent_vc.subject_did}) does not match issuer of delegated VC ({presented_vc_issuer_did}).")

    try:
        parent_cs_model = CredentialSubjectWithSkillsModel(**parent_vc.model.credentialSubject)
    except (ValidationError, TypeError) as e:
        # This error is about the parent VC's structure, which should be valid if it passed earlier checks.
        # However, if credentialSubject is malformed specifically for delegation checks, this catches it.
        logger.error(f"Parent VC ({parent_vc.id}) credentialSubject format error during delegation permission check: {e}")
        raise HTTPException(status_code=500, detail=f"Parent VC ({parent_vc.id}) credentialSubject malformed for delegation check.")
    logger.info(f"Parent VC ({parent_vc.id}) credentialSubject: {parent_cs_model}")
    logger.info(f"Parent VC ({parent_vc.id}) conditions: {parent_cs_model.conditions}")
    
    delegation_allowed = False
    # Check for `canDelegate: true` in top-level conditions
    if parent_cs_model.conditions and parent_cs_model.conditions.get("canDelegate") is True:
        delegation_allowed = True
    else:
        # If not in top-level, check within skills using the raw credentialSubject dict
        cs_raw = parent_vc.model.credentialSubject
        if isinstance(cs_raw, dict) and 'skills' in cs_raw and isinstance(cs_raw['skills'], list):
            if any(isinstance(skill, dict) and skill.get("canDelegate") is True for skill in cs_raw['skills']):
                delegation_allowed = True

    if not delegation_allowed:
        logger.info(f"Parent VC ({parent_vc.id}) does not allow delegation (canDelegate is not true in conditions or skills).")
        raise HTTPException(status_code=403, detail=f"Delegation not permitted: Parent VC ({parent_vc.id}) does not allow delegation (canDelegate is not true in conditions or skills).")

    # Optional: Check for delegableSkills if that logic is to be enforced here.
    # For now, just checking canDelegate is sufficient as per original logic.
    logger.info(f"Parent VC ({parent_vc.id}) permits delegation to {presented_vc_issuer_did}.")

async def verify_delegated_ldp_vc(presented_vc: VerifiableCredential) -> VerifiableCredential:
    """
    Verifies a delegated LDP VC, including its delegation chain.
    Assumes presented_vc's own signature and basic validity (expiration, revocation) have been checked.
    """
    logger.info(f"Verifying delegated LDP VC {presented_vc.id}")
    if not presented_vc.model or not presented_vc.model.credentialSubject:
        raise HTTPException(status_code=400, detail="Presented VC model or credentialSubject is missing for delegation check.")

    try:
        current_cs_model = CredentialSubjectWithSkillsModel(**presented_vc.model.credentialSubject)
    except (ValidationError, TypeError) as e:
        raise HTTPException(status_code=400, detail=f"Presented VC credentialSubject format error for delegation: {e}")

    # Validate delegation rules and get parent_vc_id_ref
    parent_vc_id_ref = await _validate_delegation_rules(presented_vc, current_cs_model)
    if not parent_vc_id_ref: # Indicates not a delegated VC or handled by _validate_delegation_rules
        return presented_vc

    # Load and Verify Parent VC
    vdr_base_url = f"http://{settings.host}:{settings.port}/api/v1/vdr"
    parent_vc = await _fetch_and_verify_parent_vc(parent_vc_id_ref, vdr_base_url)

    # Parent VC is now fetched, parsed, and its own validity (signature, expiry, revocation) is confirmed.
    # Now, check the delegation linkage and permissions.
    await _check_parent_delegation_permission(parent_vc, presented_vc.issuer_did)

    # Optional: Check if the *specific skills* being exercised by presented_vc are permitted by parent_cs_model.conditions.get("delegableSkills", [])
    # This would require comparing skills in current_cs_model with parent_cs_model.conditions.get("delegableSkills", [])

    logger.info(f"All delegation checks passed for VC {presented_vc.id} (parent: {parent_vc.id}).")
    return presented_vc # Return the originally presented (and now fully verified delegated) VC

async def get_final_verified_vc(vc: VerifiableCredential = Depends(get_verified_vc_from_auth)) -> VerifiableCredentialModel:
    """
    FastAPI dependency that first gets a verified VC (signature, basic checks)
    and then performs delegation chain verification if applicable.
    Returns the Pydantic model of the *presented* VC if all checks pass.
    """
    logger.info(f"Getting final verified VC for {vc.id}")
    final_vc_instance = await verify_delegated_ldp_vc(vc)
    if not final_vc_instance.model:
        # Should not happen if verify_delegated_ldp_vc succeeds and returns a valid VC instance
        raise HTTPException(status_code=500, detail="Failed to obtain final VC model after all checks.")
    return final_vc_instance.model # Return the Pydantic model of the presented VC


# --- FastAPI Application ---
router = APIRouter()

agent_card = AgentCard(
                name="Map Agent",
                description="This agent will give you a map of the region you ask for",
                url="http://localhost:8050",
                provider=AgentProvider(
                    organization="Google, Inc.", url="https://google.com"
                ),
                iconUrl="https://georoute-agent.example.com/icon.png",
                version="1.0.0",
                documentationUrl="http://localhost:8050/docs",
                capabilities=AgentCapabilities(
                    streaming=False,
                    pushNotifications=False,
                    stateTransitionHistory=False,
                ),
                securitySchemes={"bearerAuth": {"type": "http", "scheme": "bearer"}},
                defaultInputModes=['text'],
                defaultOutputModes=['text'],

                skills=[
                    AgentSkill(
                        id='google-maps',
                        name='Generate a map of the region you ask for',
                        description='Generate a map of the region you ask for',
                        tags=['map:generate'],
                        examples=['generate a map of the declared region'],
                        inputModes=['text'],
                        outputModes=['text'],
                    )
                ],
                supportsAuthenticatedExtendedCard=False,
            )

@router.get("/.well-known/agent.json")
async def get_agent_card(request: Request) -> dict:
    return agent_card.model_dump(exclude_none=True)

@router.post("/map/generate", response_model=MapGenerationResponse)
# Use the new dependency that handles full LDP VC verification including delegation
async def generate_map(params: MapGenerationParams, verified_vc_model: VerifiableCredentialModel = Depends(get_final_verified_vc)):
    # verified_vc_model is the Pydantic model of the *presented* VC, after all checks.

    # Skill/Scope Check on the (potentially delegated) verified VC model
    logger.info(f"Generating map with params: {params}")
    try:
        presented_cs_model = CredentialSubjectWithSkillsModel(**verified_vc_model.credentialSubject)
    except (ValidationError, TypeError) as e:
        raise HTTPException(status_code=400, detail=f"Presented VC credentialSubject format error after verification: {e}")
    logger.info(f"Presented VC credentialSubject: {presented_cs_model}")
    logger.info(f"Presented VC skills: {presented_cs_model.skills}")
    logger.info(f"Presented VC skills granted: {presented_cs_model.skills[0].granted}")
    logger.info(f"Presented VC skills scope: {presented_cs_model.skills[0].scope}")
    logger.info(f"Type of scope: {type(presented_cs_model.skills[0].scope)}")
    has_scope = any(
        "map:generate" in skill.scope and skill.granted is True
        for skill in presented_cs_model.skills
    )
    logger.info(f"Has scope: {has_scope}")
    if not has_scope:
        logger.error(f"received skill scope: {presented_cs_model.skills[0].scope}")
        raise HTTPException(status_code=403, detail="Skill 'map:generate' not granted or not found in the presented VC.")

    logger.info(f"/map/generate API call authorized for VC ID: {verified_vc_model.id}, Subject: {presented_cs_model.id}")
    logger.info(f"Map generation requested with region: '{params.region}', style: '{params.style}'.")

    return MapGenerationResponse(
        status=f"✅ Map generation initiated for region: {params.region}, style: {params.style}!",
        region=params.region,
        style=params.style
    )
