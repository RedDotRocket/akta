from typing import List, Union
from pydantic import BaseModel, Field, HttpUrl
from datetime import datetime


class Skill(BaseModel):
    id: str
    granted: bool
    scope: List[str]
    usageLimit: int


class CredentialSubject(BaseModel):
    id: str
    skills: List[Skill]


class Evidence(BaseModel):
    id: Union[str, HttpUrl]
    type: str
    description: str
    hash: str


class VerifiableCredential(BaseModel):
    context: List[str] = Field(..., alias='@context')
    id: str
    type: List[str]
    issuer: str
    issuanceDate: datetime
    credentialSubject: Union[CredentialSubject, dict]
    evidence: List[Evidence]

# === DID Document Models ===

class VerificationMethod(BaseModel):
    id: str
    type: str
    controller: str
    publicKeyMultibase: str

class DIDService(BaseModel):
    id: str
    type: str
    serviceEndpoint: Union[str, HttpUrl]

class DIDDocument(BaseModel):
    context: List[str] = Field(..., alias='@context')
    id: str
    verificationMethod: List[VerificationMethod]
    authentication: List[str]
    assertionMethod: List[str]
    keyAgreement: List[str]
    capabilityInvocation: List[str]
    capabilityDelegation: List[str]
    service: List[DIDService]
