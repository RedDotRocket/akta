import base64
import json
from datetime import UTC, datetime
from typing import Optional

import base58
import httpx
from fastapi import Depends, Header, HTTPException
from nacl.signing import VerifyKey
from credentials import VerifiableCredential
from models import (
    CredentialSubjectWithSkillsModel,
    DIDDocumentModel,
    VerifiableCredentialModel,
)
from pydantic import ValidationError

from akta.config import settings
from akta.logging import get_logger

logger = get_logger(__name__)


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
            logger.info(f"Attempting to fetch DID Document from: {did_doc_url}")

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
        logger.warning(f"HTTPException during single LDP VC signature verification for {vc.id if vc else 'Unknown VC'}: {e.detail}")
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
    # else: Consider policy on VDR missing expirationDate
    #     logger.warning(f"Presented VC {vc_instance.id} missing 'expirationDate'. Policy might reject this.")

    return vc_instance

async def _fetch_and_verify_parent_vc(parent_vc_id_ref: str, vc_store_base_url: str) -> VerifiableCredential:
    """Fetches, parses, and verifies a parent VC (signature, expiration, revocation)."""
    parent_vc: Optional[VerifiableCredential] = None
    try:
        logger.info(f"Retrieving parent VC {parent_vc_id_ref} from VC store: {vc_store_base_url}/vdr/{parent_vc_id_ref}")
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{vc_store_base_url}/vdr/{parent_vc_id_ref}")
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
        raise HTTPException(status_code=403, detail=f"Delegation fraud: Issuer of delegated VC ({presented_vc.issuer_did}) does not match delegationDetails.delegatedBy ({delegated_by_did}).")

    try:
        delegation_exp_date = parse_datetime_utc(delegation_valid_until_str)
        if datetime.now(UTC) > delegation_exp_date:
            raise HTTPException(status_code=403, detail=f"Delegation itself has expired as of {delegation_exp_date.isoformat()}.")
    except ValueError as e: # Catches errors from parse_datetime_utc
        raise HTTPException(status_code=400, detail=f"Invalid validUntil format in delegationDetails: {e}")

    # Return key details if needed by caller, though side-effects (exceptions) are primary
    return parent_vc_id_ref

async def _check_parent_delegation_permission(parent_vc: VerifiableCredential, presented_vc_issuer_did: str):
    """Checks if the parent VC permits delegation to the issuer of the presented VC."""
    if parent_vc.subject_did != presented_vc_issuer_did:
        raise HTTPException(status_code=403, detail=f"Delegation chain broken: Subject of parent VC ({parent_vc.subject_did}) does not match issuer of delegated VC ({presented_vc_issuer_did}).")

    try:
        parent_cs_model = CredentialSubjectWithSkillsModel(**parent_vc.model.credentialSubject)
    except (ValidationError, TypeError) as e:
        # This error is about the parent VC's structure, which should be valid if it passed earlier checks.
        # However, if credentialSubject is malformed specifically for delegation checks, this catches it.
        logger.error(f"Parent VC ({parent_vc.id}) credentialSubject format error during delegation permission check: {e}")
        raise HTTPException(status_code=500, detail=f"Parent VC ({parent_vc.id}) credentialSubject malformed for delegation check.")

    if not parent_cs_model.conditions or parent_cs_model.conditions.get("canDelegate") is not True:
        raise HTTPException(status_code=403, detail=f"Delegation not permitted: Parent VC ({parent_vc.id}) does not allow delegation (canDelegate is not true or conditions missing).")

    # Optional: Check for delegableSkills if that logic is to be enforced here.
    # For now, just checking canDelegate is sufficient as per original logic.
    logger.info(f"Parent VC ({parent_vc.id}) permits delegation to {presented_vc_issuer_did}.")

async def verify_delegated_ldp_vc(presented_vc: VerifiableCredential) -> VerifiableCredential:
    """
    Verifies a delegated LDP VC, including its delegation chain.
    Assumes presented_vc's own signature and basic validity (expiration, revocation) have been checked.
    """
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
    vc_store_base_url = f"http://{settings.host}:{settings.port}/api/v1/vc-store"
    parent_vc = await _fetch_and_verify_parent_vc(parent_vc_id_ref, vc_store_base_url)

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
    final_vc_instance = await verify_delegated_ldp_vc(vc)
    if not final_vc_instance.model:
        # Should not happen if verify_delegated_ldp_vc succeeds and returns a valid VC instance
        raise HTTPException(status_code=500, detail="Failed to obtain final VC model after all checks.")
    return final_vc_instance.model # Return the Pydantic model of the presented VC


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