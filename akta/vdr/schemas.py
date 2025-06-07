from typing import Optional

from pydantic import BaseModel, Field
from datetime import datetime


class VCPublishRequest(BaseModel):
    verifiable_credential: dict

class VCPublishResponse(BaseModel):
    status: str
    vc_id: str
    message: Optional[str] = None

# Schema for the data stored in the database (SQLAlchemy model will be based on this)
class StoredVCBase(BaseModel):
    vc_id: str = Field(primary_key=True, index=True)
    ldp_vc_json: str # Storing the full LDP VC as a JSON string
    issuer_did: Optional[str] = Field(default=None, index=True)
    subject_did: Optional[str] = Field(default=None, index=True)
    issuance_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None

    class Config:
        from_attributes = True # Pydantic ORM mode to work with SQLAlchemy models

class StoredVCCreate(StoredVCBase):
    pass # All fields from base are needed for creation

class StoredVC(StoredVCBase):
    # Fields added by the database automatically (e.g., auto-increment ID, created_at)
    # For SQLite, rowid is implicit. If using a specific auto-incrementing primary key field:
    # id: int
    created_at: datetime
    updated_at: datetime
