import json
import uuid
from datetime import datetime, UTC
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError
from typing import Dict, Any, Optional, List, Union


from pyld import jsonld
from pyld.documentloader.requests import requests_document_loader
import base58

from .models import ProofModel, VerifiableCredentialModel
from .exceptions import (
    AktaError,
    SignatureError,
    NormalizationError,
    VCValidationError,
)


class VerifiableCredential:
    """Represents a Verifiable Credential (VC), using Pydantic for data management and Linked Data Proofs."""

    DEFAULT_TYPE = [
        "VerifiableCredential",
        "AgentSkillAccess",
    ]  # Example, can be overridden

    def __init__(self, data: Optional[Dict[str, Any]] = None):
        """
        Initializes the VerifiableCredential.
        If `data` is provided, it's parsed into the internal Pydantic model.
        Otherwise, the internal model is None until `build()` or `from_dict/json()` is called.
        """
        self.model: Optional[VerifiableCredentialModel] = None
        if data:
            # Handle the "@context" alias if present in the input dictionary
            if "@context" in data and "context" not in data:
                data["context"] = data.pop("@context")
            try:
                self.model = VerifiableCredentialModel(**data)
            except Exception as e:  # Catch Pydantic validation errors
                # Potentially re-raise as a custom error or handle
                print(f"Error initializing VerifiableCredentialModel: {e}")
                raise VCValidationError(f"Error initializing VerifiableCredentialModel: {e}") from e

    def build(
        self,
        issuer_did: str,
        subject_did: str,
        credential_id: Optional[str] = None,
        types: Optional[List[str]] = None,
        contexts: Optional[Union[List[Union[str, Dict]], str]] = None,
        issuance_date: Optional[datetime] = None,
        expiration_date: Optional[datetime] = None,
        credential_subject: Optional[Dict[str, Any]] = None,
    ) -> "VerifiableCredential":
        """Builds the VC data structure (unsigned) using the Pydantic model."""
        now = datetime.now(UTC)

        vc_data = {
            "@context": contexts
            if contexts is not None
            else VerifiableCredentialModel.model_fields["context"].default,
            "id": credential_id or f"urn:uuid:{str(uuid.uuid4())}",
            "type": types or self.DEFAULT_TYPE,
            "issuer": issuer_did,
            "issuanceDate": issuance_date or now,
            "expirationDate": expiration_date,
            "credentialSubject": credential_subject or {"id": subject_did},
        }

        try:
            self.model = VerifiableCredentialModel(**vc_data)
        except Exception as e:
            print(f"Error building VerifiableCredentialModel: {e}")
            raise VCValidationError(f"Error building VerifiableCredentialModel: {e}") from e
        return self

    def sign(
        self,
        issuer_signing_key: SigningKey,
        verification_method_id: str,
        proof_purpose: Optional[str] = "assertionMethod",
    ) -> "VerifiableCredential":
        """Signs the VC and adds the proof block to the Pydantic model."""
        if not self.model:
            raise AktaError("VC data model must be built or loaded before signing.")

        proof_options = {
            "type": "Ed25519Signature2020",
            "created": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "verificationMethod": verification_method_id,
            "proofPurpose": proof_purpose,
        }

        # Prepare document for canonicalization
        # 1. Get the VC model as a dictionary.
        # To ensure all datetimes are strings as expected by JSON-LD context (e.g. xsd:dateTime),
        # we serialize the entire model to a JSON string (which applies json_encoders)
        # and then parse it back to a Python dict.
        vc_json_string = self.model.model_dump_json(by_alias=True, exclude_none=True)
        doc_to_canonicalize = json.loads(vc_json_string)

        # Remove the 'proof' field if it was included from the model dump,
        # as we are constructing a new one for signing or adding to an existing one.
        if "proof" in doc_to_canonicalize:
            del doc_to_canonicalize["proof"]

        # 2. Add the proof options (without proofValue) to this dictionary
        doc_to_canonicalize["proof"] = proof_options

        # 3. Ensure datetime fields are ISO 8601 strings with 'Z' if not already done by model_dump
        # Pydantic's json_encoders in the model should handle this for issuanceDate/expirationDate during model_dump.
        # The 'created' field in proof_options is already an ISO string.

        # Canonicalize using URDNA2015 algorithm
        # The `jsonld` library expects the document itself, not a JSON string.
        try:
            doc_loader = requests_document_loader()
            normalized_doc_nquads = jsonld.normalize(
                doc_to_canonicalize,
                options={
                    "algorithm": "URDNA2015",
                    "format": "application/n-quads",
                    "documentLoader": doc_loader,
                },
            )
        except Exception as e:
            print(f"Error during JSON-LD normalization: {e}")
            raise NormalizationError(f"JSON-LD Normalization failed: {e}") from e

        # Sign the canonicalized N-Quads string (UTF-8 encoded)
        signature_bytes = issuer_signing_key.sign(
            normalized_doc_nquads.encode("utf-8")
        ).signature

        # Base58btc encode the signature
        proof_value_b58 = base58.b58encode(signature_bytes).decode("utf-8")

        # Create the final proof model including the proofValue
        final_proof_data = {**proof_options, "proofValue": proof_value_b58}
        try:
            self.model.proof = ProofModel(
                **final_proof_data
            )  # ProofModel type is Ed25519Signature2020 by default
        except Exception as e:
            print(f"Error creating ProofModel for LDP: {e}")
            raise AktaError(f"Error creating ProofModel for LDP: {e}") from e
        return self

    def verify_signature(
        self,
        issuer_public_key: VerifyKey,
        expected_issuer_did: Optional[str] = None,
        expected_subject_did: Optional[str] = None,
    ) -> bool:
        """Verifies the VC's signature using data from the Pydantic model."""
        if not self.model or not self.model.proof or not self.model.proof.proofValue:
            print(
                "❌ VC model, proof, or proof.proofValue is missing for LDP verification."
            )
            raise VCValidationError("VC model, proof, or proof.proofValue is missing for LDP verification.")

        stored_proof = self.model.proof
        proof_value_b58 = stored_proof.proofValue

        # Prepare document for canonicalization (VC with proof options, excluding proofValue)
        # Serialize to JSON and back to ensure all datetimes are strings as JSON-LD expects for xsd:dateTime
        vc_json_string = self.model.model_dump_json(by_alias=True, exclude_none=True)
        doc_to_verify = json.loads(vc_json_string)

        # The document for verification must contain the proof block but WITHOUT the proofValue.
        # doc_to_verify currently has the full proof including proofValue from the model dump.
        # We need to ensure the 'proof' dictionary used for normalization matches the one used during signing (i.e., without proofValue).
        if "proof" in doc_to_verify and isinstance(doc_to_verify["proof"], dict):
            # Modify the 'proof' dict in place by removing 'proofValue'.
            # The other fields like 'created', 'verificationMethod' etc., which were part of the original
            # proof options during signing, will remain. Pydantic's json_encoders for ProofModel
            # would have ensured 'created' is a string in vc_json_string.
            if "proofValue" in doc_to_verify["proof"]:
                del doc_to_verify["proof"]["proofValue"]
            # No need to re-assign doc_to_verify["proof"], modification is in-place.
        else:
            # This should not happen if a proof exists and is being verified.
            print(
                "Error: Proof block is missing or not a dictionary in loaded VC for verification."
            )
            raise VCValidationError("Proof block is missing or not a dictionary in loaded VC for verification.")

        # Ensure datetime fields are ISO strings as they would have been during signing
        # Pydantic models with json_encoders should manage this upon model_dump.

        try:
            doc_loader = requests_document_loader()
            normalized_doc_nquads = jsonld.normalize(
                doc_to_verify,
                options={
                    "algorithm": "URDNA2015",
                    "format": "application/n-quads",
                    "documentLoader": doc_loader,
                },
            )
        except Exception as e:
            print(f"Error during JSON-LD normalization for verification: {e}")
            raise NormalizationError(f"Error during JSON-LD normalization for verification: {e}") from e

        # Decode the base58btc proofValue to raw signature bytes
        try:
            signature_bytes = base58.b58decode(proof_value_b58)
        except Exception as e:
            print(f"❌ Error decoding base58 proofValue: {e}")
            raise SignatureError(f"Error decoding base58 proofValue: {e}") from e

        # Cryptographic verification block
        try:
            # Verify the signature against the canonicalized document
            issuer_public_key.verify(
                normalized_doc_nquads.encode("utf-8"), signature_bytes
            )
        except BadSignatureError as e: # Specific catch for nacl's BadSignatureError
            print(
                "❌ Signature verification failed: Invalid LDP signature (BadSignatureError)."
            )
            raise SignatureError("Invalid LDP signature (BadSignatureError)") from e
        except ValueError as e: # Catch other ValueErrors that might occur during verification
            print(f"❌ Signature verification failed: Value error - {e}")
            raise SignatureError(f"Signature verification failed: Value error - {e}") from e
        # except Exception as e: # Removing the overly broad Exception here, or making it more specific if necessary
        #     print(
        #         f"❌ An unexpected error occurred during LDP signature verification: {e}"
        #     )
        #     raise SignatureError(f"An unexpected error occurred during LDP signature verification: {e}") from e

        # Semantic checks (perform only if cryptographic verification passed)
        if expected_issuer_did and self.model.issuer != expected_issuer_did:
            print(
                f"❌ Issuer DID mismatch. Expected {expected_issuer_did}, got {self.model.issuer}"
            )
            raise VCValidationError(f"Issuer DID mismatch. Expected {expected_issuer_did}, got {self.model.issuer}")
        if expected_subject_did:
            cs_id = (
                self.model.credentialSubject.get("id")
                if self.model.credentialSubject
                else None
            )
            if cs_id != expected_subject_did:
                print(
                    f"❌ Subject DID mismatch. Expected {expected_subject_did}, got {cs_id}"
                )
                raise VCValidationError(f"Subject DID mismatch. Expected {expected_subject_did}, got {cs_id}")
        return True

    @property
    def id(self) -> Optional[str]:
        return self.model.id if self.model else None

    @property
    def issuer_did(self) -> Optional[str]:
        return self.model.issuer if self.model else None

    @property
    def subject_did(self) -> Optional[str]:
        if self.model and self.model.credentialSubject:
            return self.model.credentialSubject.get("id")
        return None

    @property
    def expiration_date(self) -> Optional[datetime]:
        return (
            self.model.expirationDate
            if self.model and self.model.expirationDate
            else None
        )

    @property
    def issuance_date(self) -> Optional[datetime]:
        return self.model.issuanceDate if self.model else None

    @property
    def proof(self) -> Optional[ProofModel]:
        return self.model.proof if self.model else None

    def is_expired(self) -> bool:
        """Checks if the VC has expired."""
        if self.model and self.model.expirationDate:
            return self.model.expirationDate < datetime.now(UTC)
        # No expiration date means it doesn't expire based on this check
        return False

    def to_dict(self) -> Dict[str, Any]:
        """Returns the VC as a dictionary, using Pydantic model dump."""
        if not self.model:
            raise AktaError("VC model is not initialized.")
        return self.model.model_dump(by_alias=True, exclude_none=True)

    def to_json(self, indent: Optional[int] = 2) -> str:
        """Returns the VC as a JSON string, using Pydantic model dump."""
        if not self.model:
            raise AktaError("VC model is not initialized.")
        return self.model.model_dump_json(
            by_alias=True, exclude_none=True, indent=indent
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VerifiableCredential":
        """Creates a VerifiableCredential instance from a dictionary."""
        # Handle @context alias if present
        if "@context" in data and "context" not in data:
            data["context"] = data.pop("@context")
        try:
            # Use a temporary VerifiableCredentialModel instance for validation and structure
            # then create the VerifiableCredential instance with it.
            vc_model = VerifiableCredentialModel(**data)
            vc_instance = cls()
            vc_instance.model = vc_model
            return vc_instance
        except Exception as e:
            # Catch Pydantic validation errors
            print(f"Error creating VerifiableCredential from_dict: {e}")
            raise VCValidationError(f"Error creating VerifiableCredential from_dict: {e}") from e

    @classmethod
    def from_json(cls, json_str: str) -> "VerifiableCredential":
        """Creates a VerifiableCredential instance from a JSON string."""
        try:
            data = json.loads(json_str)
            return cls.from_dict(data)
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON for VerifiableCredential: {e}")
            raise AktaError(f"Error decoding JSON for VerifiableCredential: {e}") from e
        except Exception as e:
            # Catch other errors like Pydantic validation from from_dict
            print(f"Error creating VerifiableCredential from_json: {e}")
            raise VCValidationError(f"Error creating VerifiableCredential from_json: {e}") from e
