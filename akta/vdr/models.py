from sqlalchemy import Column, String, Text, DateTime, func
from akta.vdr.database import Base

class StoredVCModel(Base):
    __tablename__ = "stored_vcs"

    vc_id = Column(String, primary_key=True, index=True, unique=True, nullable=False)
    ldp_vc_json = Column(Text, nullable=False)

    issuer_did = Column(String, index=True, nullable=True)
    subject_did = Column(String, index=True, nullable=True)

    issuance_date = Column(DateTime(timezone=True), nullable=True)
    expiration_date = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    def __repr__(self):
        return f"<StoredVCModel(vc_id='{self.vc_id}', issuer_did='{self.issuer_did}')>"