import json
from typing import Optional

from sqlalchemy.orm import Session

from akta.models import VerifiableCredentialModel as MainVDRSchema
from . import models as db_models  # SQLAlchemy models (StoredVCModel)


def get_vc_by_id(db: Session, vc_id: str) -> Optional[db_models.StoredVCModel]:
    """Retrieves a VC from the database by its ID."""
    return db.query(db_models.StoredVCModel).filter(db_models.StoredVCModel.vc_id == vc_id).first()

def create_ldp_vc(
    db: Session,
    ldp_vc_data: dict,
) -> db_models.StoredVCModel:
    """
    Processes a Verifiable Credential (LDP) dictionary, extracts key information,
    and stores it in the database.

    Args:
        db: SQLAlchemy database session.
        ldp_vc_data: The full Verifiable Credential (LDP) as a Python dictionary.

    Returns:
        The created StoredVCModel instance.

    Raises:
        ValueError: If essential VC data (id, issuer) is missing from ldp_vc_data.
    """
    try:
        parsed_vc = MainVDRSchema(**ldp_vc_data)
    except Exception as e:
        raise ValueError(f"Failed to parse provided LDP VC data: {e}")

    vc_id = parsed_vc.id
    issuer_did = parsed_vc.issuer

    if not vc_id:
        raise ValueError("LDP VC data is missing the 'id' field.")

    subject_did = parsed_vc.credentialSubject.get("id") if parsed_vc.credentialSubject else None
    issuance_date = parsed_vc.issuanceDate
    expiration_date = parsed_vc.expirationDate

    try:
        ldp_vc_json_str = json.dumps(ldp_vc_data)
    except TypeError as e:
        raise ValueError(f"Could not serialize LDP VC data to JSON: {e}")

    db_vc = db_models.StoredVCModel(
        vc_id=vc_id,
        ldp_vc_json=ldp_vc_json_str,
        issuer_did=issuer_did,
        subject_did=subject_did,
        issuance_date=issuance_date,
        expiration_date=expiration_date,
    )
    db.add(db_vc)
    db.commit()
    db.refresh(db_vc)
    return db_vc

