import json
from typing import Optional, Dict

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session

from akta.config import settings
from akta.vdr import crud
from akta.vdr import schemas as vdr_schemas
from akta.vdr.database import get_db
from akta.logging import get_logger

logger = get_logger(__name__)

# Placeholder for API Key security. In a real app, use FastAPI's security utilities.
# Example: X-API-Key: yoursecureapikey
VC_STORE_API_KEY = settings.app_name + "_vc_store_secret_key" # Replace with a real secret from config/env

router = APIRouter(
    tags=["Verifiable Credential Store"],
)

def verify_api_key(x_api_key: Optional[str] = Header(None)):
    # In a real app, use a more secure way to manage and verify API keys (e.g., secrets management, hashed keys)
    if not x_api_key:
        raise HTTPException(status_code=401, detail="X-API-Key header missing.")
    if x_api_key != VC_STORE_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid X-API-Key.")
    return True

@router.post("/vdr", response_model=vdr_schemas.VCPublishResponse)
async def publish_vc(
    vc_publish_request: vdr_schemas.VCPublishRequest,
    db: Session = Depends(get_db),
    #_=Depends(verify_api_key) # Uncomment to enable API key check
):
    """
    Publishes a new Verifiable Credential (LDP) to the store.

    - **verifiable_credential**: The full LDP Verifiable Credential as a JSON object (dict).

    *Protected endpoint (conceptual API key check commented out for now).*
    """
    logger.info("Received request to publish LDP VC. API Key check is currently bypassed.")

    ldp_vc_data = vc_publish_request.verifiable_credential
    vc_id = ldp_vc_data.get("id")

    if not vc_id:
        raise HTTPException(status_code=400, detail="LDP VC data missing 'id' field.")

    db_vc = crud.get_vc_by_id(db, vc_id=vc_id)
    if db_vc:
        try:
            existing_ldp_vc_data = json.loads(db_vc.ldp_vc_json)
        except json.JSONDecodeError:
            # This would indicate an issue with data integrity in the DB
            raise HTTPException(status_code=500, detail=f"Failed to parse existing VC {vc_id} from store.")

        # Idempotency: If same VC ID and content, consider it a success
        if existing_ldp_vc_data == ldp_vc_data:
            return vdr_schemas.VCPublishResponse(
                status="success",
                vc_id=vc_id,
                message="VC with this ID and content already exists. No action taken."
            )
        else:
            # Different content for the same ID - could be an update or an error based on policy
            # For now, let's treat it as a conflict if content differs.
            raise HTTPException(
                status_code=409,
                detail=f"VC with ID '{vc_id}' already exists but with different content. Update not supported or conflict."
            )
    try:
        created_db_vc = crud.create_ldp_vc(db=db, ldp_vc_data=ldp_vc_data)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        # Catch-all for other unexpected errors during VC creation
        logger.error(f"Unexpected error publishing LDP VC {vc_id}: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred while publishing the LDP VC: {type(e).__name__}")

    return vdr_schemas.VCPublishResponse(
        status="success",
        vc_id=created_db_vc.vc_id,
        message="LDP VC published successfully."
    )

@router.get("/vdr/{vc_id_path}", response_model=Dict)
async def retrieve_vc(
    vc_id_path: str,
    db: Session = Depends(get_db)
):
    """
    Retrieves a Verifiable Credential (LDP) by its full ID (e.g., urn:uuid:...).
    Returns the full LDP VC as a JSON object.
    """
    db_vc = crud.get_vc_by_id(db, vc_id=vc_id_path)
    if db_vc is None:
        raise HTTPException(status_code=404, detail=f"VC with ID '{vc_id_path}' not found.")

    try:
        # Parse the stored JSON string back into a Python dictionary
        ldp_vc_data = json.loads(db_vc.ldp_vc_json)
        return ldp_vc_data
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail=f"Failed to parse stored LDP VC JSON for VC ID '{vc_id_path}'. Data integrity issue.")
    except Exception as e:
        logger.error(f"Unexpected error retrieving LDP VC {vc_id_path}: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred while retrieving the LDP VC: {type(e).__name__}")