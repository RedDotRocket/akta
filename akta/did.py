from typing import Any, Dict, List, Optional

import base58
import httpx
import json
from nacl.signing import SigningKey, VerifyKey
from pydantic import ValidationError

from .models import DIDDocumentModel, DIDKeyModel, DIDWebModel, VerificationMethodModel
from .exceptions import DIDResolutionError, AktaError


def _public_bytes_to_multibase_ed25519(key_bytes: bytes) -> str:
    # Ed25519 public key multicodec prefix (0xed01)
    # 0xed -> Ed25519 public key
    # 0x01 -> varint encoding of the length of the key (32 bytes).
    # Actually, for Ed25519, 0xed is the code, and the 0x01 appears to be part of the varint representation of the code itself,
    # or a historically used prefix component. The raw key directly follows.
    # Standard multicodec for ed25519-pub is 0xed.
    # However, did:key often uses a 2-byte prefix 0xed01 before the 32-byte key.
    # Let's stick to what's common for did:key context.
    codec_prefix = bytes(
        [0xED, 0x01]
    )  # Prefix for Ed25519 public key in did:key context
    multicodec_pubkey = codec_prefix + key_bytes
    return "z" + base58.b58encode(multicodec_pubkey).decode("utf-8")


def _multibase_ed25519_to_public_bytes(multibase_key: str) -> bytes:
    if not multibase_key.startswith("z"):
        raise AktaError("Ed25519 Multibase key must start with 'z'")
    try:
        multicodec_pubkey = base58.b58decode(multibase_key[1:])
    except ValueError as e:
        raise AktaError(f"Invalid base58 encoding in public key: {e}") from e

    # Expecting 0xed01 prefix then 32 bytes of key
    if (
        multicodec_pubkey.startswith(bytes([0xED, 0x01]))
        and len(multicodec_pubkey) == 34
    ):
        return multicodec_pubkey[2:]
    # Support for just 0xed prefix (less common in did:key but possible)
    elif multicodec_pubkey.startswith(bytes([0xED])) and len(multicodec_pubkey) == 33:
        return multicodec_pubkey[1:]
    else:
        raise AktaError("Invalid Ed25519 multicodec prefix or key length.")


def _private_seed_to_multibase(seed_bytes: bytes) -> str:
    # Simply base58btc encode the 32-byte seed.
    # No 'z' prefix for private keys, it's just the encoded seed.
    return base58.b58encode(seed_bytes).decode("utf-8")


def _multibase_to_private_seed(multibase_seed: str) -> bytes:
    return base58.b58decode(multibase_seed)


def get_verify_key_from_multibase(pk_multibase: str) -> VerifyKey:
    """Converts an Ed25519 public key from multibase format to a VerifyKey object."""
    public_key_bytes = _multibase_ed25519_to_public_bytes(pk_multibase)
    return VerifyKey(public_key_bytes)


def resolve_verification_key(
    verification_method_url: str,
    issuer_did_hint: Optional[str] = None,
    did_web_scheme: str = "https",
) -> Optional[VerifyKey]:
    """Resolves the public verification key from a verification method URL or an issuer DID hint."""

    target_vm_url = verification_method_url  # Primarily use the VM from the proof
    did_to_resolve = issuer_did_hint

    if not target_vm_url and issuer_did_hint:
        # If only issuer_did_hint is provided, we assume it might be a did:key that IS the verification method
        if issuer_did_hint.startswith("did:key:"):
            target_vm_url = issuer_did_hint  # For did:key, the DID itself can be the VM
        else:
            # For other did methods, if no explicit VM in proof, we can't proceed without more info
            # or a convention (e.g. did_doc.verificationMethod[0]) which is risky.
            # Returning None if resolution is not possible without erroring.
            return None
    elif not target_vm_url:
        raise DIDResolutionError(
            "No verificationMethod in VC proof and no issuer_did hint provided."
        )

    # Priority 1: Direct resolution if verification_method_url itself is a full did:key URI (with fragment)
    # e.g. did:key:zABC#zABC
    if target_vm_url.startswith("did:key:"):
        try:
            # The DIDKey constructor can often handle the full VM URL if it's just did#publicKeyMultibase
            # Or, if it's the DID itself, it will resolve its own key.
            key_did_string = target_vm_url.split("#")[0]
            # Note: DIDKey() is called here, not self.DIDKey() as it's a module function now
            did_key_resolver = DIDKey(did_string=key_did_string)

            # Check if the fragment (publicKeyMultibase) matches the resolved key's multibase
            # This ensures the specified key in the fragment is indeed THE key of the DID.
            if "#" in target_vm_url:
                fragment = target_vm_url.split("#")[1]
                if fragment != did_key_resolver.public_key_multibase:
                    raise DIDResolutionError(
                        f"Fragment {fragment} in did:key verification method {target_vm_url} does not match the resolved public key {did_key_resolver.public_key_multibase}."
                    )

            if not did_key_resolver.verify_key:
                raise DIDResolutionError(
                    f"Could not derive public key from did:key: {target_vm_url}"
                )
            # Successfully resolved
            return did_key_resolver.verify_key
        except Exception as e:
            raise DIDResolutionError(f"Error resolving did:key {target_vm_url}: {e}")

    elif target_vm_url.startswith("did:web:"):
        did_string_no_fragment = target_vm_url.split("#")[0]
        identifier_after_prefix = did_string_no_fragment[len("did:web:") :]
        parts = identifier_after_prefix.split(":")
        host_plus_port = parts[0]
        path_start_index = 1

        if ":" not in parts[0] and len(parts) > 1 and parts[1].isdigit():
            host_plus_port = f"{parts[0]}:{parts[1]}"
            path_start_index = 2

        path_segments = parts[path_start_index:]
        url_path_part = "/".join(segment for segment in path_segments if segment)

        if not url_path_part:
            did_doc_url = f"{did_web_scheme}://{host_plus_port}/.well-known/did.json"
        else:
            did_doc_url = (
                f"{did_web_scheme}://{host_plus_port}/{url_path_part}/did.json"
            )

        try:
            response = httpx.get(did_doc_url, timeout=10.0)
            response.raise_for_status()
            did_doc_data = response.json()
            did_doc = DIDDocumentModel(**did_doc_data)
        except httpx.HTTPStatusError as e:
            raise DIDResolutionError(
                f"Error fetching DID Document from {did_doc_url}: HTTP {e.response.status_code}"
            ) from e
        except httpx.RequestError as e:
            raise DIDResolutionError(
                f"Error fetching DID Document from {did_doc_url}: {e}"
            ) from e
        except (json.JSONDecodeError, ValidationError) as e:
            raise DIDResolutionError(
                f"Error parsing DID Document from {did_doc_url}: {e}"
            ) from e

        found_vm_model = None
        for vm_model in did_doc.verificationMethod:
            if vm_model.id == target_vm_url:
                found_vm_model = vm_model
                break

        if not found_vm_model or not found_vm_model.publicKeyMultibase:
            raise DIDResolutionError(
                f"Verification method {target_vm_url} not found or has no publicKeyMultibase in DID Document {did_doc_url}."
            )

        try:
            verify_key = get_verify_key_from_multibase(
                found_vm_model.publicKeyMultibase
            )
            return verify_key
        except AktaError as e:
            raise DIDResolutionError(
                f"Error parsing publicKeyMultibase from resolved VM {found_vm_model.id}: {e}"
            ) from e

    elif did_to_resolve:
        if did_to_resolve.startswith("did:key:"):
            try:
                # Note: DIDKey() is called here
                did_key_resolver = DIDKey(did_string=did_to_resolve.split("#")[0])
                if "#" in target_vm_url:
                    vm_fragment = target_vm_url.split("#")[1]
                    if vm_fragment != did_key_resolver.public_key_multibase:
                        raise DIDResolutionError(
                            f"Verification method {target_vm_url} publicKeyMultibase does not match that of the provided issuer DID {did_to_resolve} ({did_key_resolver.public_key_multibase})."
                        )
                elif (
                    target_vm_url != did_key_resolver.did
                    and target_vm_url
                    != f"{did_key_resolver.did}#{did_key_resolver.public_key_multibase}"
                ):
                    raise DIDResolutionError(
                        f"Verification method {target_vm_url} does not match the provided issuer DID {did_to_resolve} or its default key ID."
                    )

                if not did_key_resolver.verify_key:
                    raise DIDResolutionError(
                        f"Could not derive public key from provided issuer_did (did:key): {did_to_resolve}"
                    )
                return did_key_resolver.verify_key
            except Exception as e:
                raise DIDResolutionError(
                    f"Error resolving provided issuer_did (did:key) {did_to_resolve}: {e}"
                )

    raise DIDResolutionError(
        f"Unsupported DID method or could not resolve key for: {target_vm_url or did_to_resolve}"
    )


class DIDKey:
    """Represents a Decentralized Identifier using the did:key method."""

    def __init__(
        self,
        private_key_multibase: Optional[str] = None,
        did_string: Optional[str] = None,
    ):
        """
        Initializes a DIDKey instance.

        The initialization follows these rules:
        1. If `did_string` is provided (e.g., "did:key:z..."), the public key is derived from it.
           No private key will be available. Only Ed25519 keys are supported.
        2. If `private_key_multibase` (base58btc encoded 32-byte seed) is provided (and `did_string` is not),
           the key pair is derived from this private key.
        3. If neither is provided, a new Ed25519 key pair is generated.

        Args:
            private_key_multibase: Optional base58btc encoded private key seed.
            did_string: Optional did:key string (e.g., "did:key:z...").
        """
        self._signing_key: Optional[SigningKey] = None
        self._verify_key: Optional[VerifyKey] = None
        self._public_key_bytes: Optional[bytes] = None
        self._did: Optional[str] = None
        self._private_key_multibase: Optional[str] = None
        self._public_key_multibase: Optional[str] = (
            None  # The 'z...' string for public key
        )
        if did_string:
            if not did_string.startswith("did:key:z"):
                raise AktaError(
                    "Invalid did:key string format. Must start with 'did:key:z'."
                )

            self._public_key_multibase = did_string[
                len("did:key:") :
            ]  # Store the 'z...' part
            self._public_key_bytes = _multibase_ed25519_to_public_bytes(
                self._public_key_multibase
            )
            self._verify_key = VerifyKey(self._public_key_bytes)
            self._did = did_string

        elif private_key_multibase:
            seed_bytes = _multibase_to_private_seed(private_key_multibase)
            self._signing_key = SigningKey(seed_bytes)
            self._verify_key = self._signing_key.verify_key
            self._public_key_bytes = self._verify_key.encode()
            self._public_key_multibase = _public_bytes_to_multibase_ed25519(
                self._public_key_bytes
            )
            self._private_key_multibase = private_key_multibase
            self._did = f"did:key:{self._public_key_multibase}"
        else:
            self._signing_key = SigningKey.generate()
            self._verify_key = self._signing_key.verify_key
            self._public_key_bytes = self._verify_key.encode()
            self._private_key_multibase = _private_seed_to_multibase(
                self._signing_key.encode()
            )
            self._public_key_multibase = _public_bytes_to_multibase_ed25519(
                self._public_key_bytes
            )
            self._did = f"did:key:{self._public_key_multibase}"

    @property
    def did(self) -> Optional[str]:
        return self._did

    @property
    def verify_key(self) -> Optional[VerifyKey]:
        return self._verify_key

    @property
    def signing_key(self) -> Optional[SigningKey]:
        return self._signing_key

    @property
    def public_key_multibase(self) -> Optional[str]:
        return self._public_key_multibase

    @property
    def public_key_bytes(self) -> Optional[bytes]:
        return self._public_key_bytes

    @property
    def private_key_multibase(self) -> Optional[str]:
        return self._private_key_multibase

    def to_dict(self) -> Dict[str, str]:
        """Returns a dictionary representation of the DID key (multibase format)."""
        if not self._did or not self._public_key_multibase:
            raise AktaError("DIDKey object is not fully initialized for to_dict.")
        data = {"did": self._did, "publicKeyMultibase": self._public_key_multibase}
        if self._private_key_multibase:
            data["privateKeyMultibase"] = self._private_key_multibase

        data["verification_method_example"] = f"{self._did}#controller"
        data["verification_method_example_did_key"] = (
            f"{self._did}#{self._public_key_multibase}"
        )

        return data

    def to_model(self) -> DIDKeyModel:
        """Returns a Pydantic model representation of the DID key."""
        if not self._did or not self._public_key_multibase:
            raise AktaError("DIDKey object is not fully initialized for to_model.")
        return DIDKeyModel(
            did=self._did,
            publicKeyMultibase=self._public_key_multibase,  # This is the 'z...' string
            privateKeyMultibase=self._private_key_multibase,
        )


class DIDWeb:
    """Represents a Decentralized Identifier using the did:web method."""

    def __init__(
        self,
        domain: str,
        path: Optional[List[str]] = None,
        private_key_multibase: Optional[str] = None,
    ):
        """
        Initializes a DIDWeb instance.

        A new Ed25519 key pair is generated unless `private_key_multibase` (base58btc encoded seed) is provided.
        The DID Document is constructed based on the domain and optional path.

        Args:
            domain: The domain name for the did:web (e.g., "example.com").
            path: Optional list of path segments for the did:web (e.g., [\"users\", \"alice\"]).
            private_key_multibase: Optional base58btc encoded private key seed.
        """
        if private_key_multibase:
            seed_bytes = _multibase_to_private_seed(private_key_multibase)
            self._signing_key = SigningKey(seed_bytes)
        else:
            self._signing_key = SigningKey.generate()

        self._verify_key = self._signing_key.verify_key
        self._public_key_bytes = self._verify_key.encode()

        self._private_key_multibase = _private_seed_to_multibase(
            self._signing_key.encode()
        )
        self._public_key_multibase = _public_bytes_to_multibase_ed25519(
            self._public_key_bytes
        )  # 'z...'

        did_web_string = f"did:web:{domain.lower()}"
        if path:
            processed_path_segments = [
                segment.strip("/") for segment in path if segment.strip("/")
            ]
            if processed_path_segments:
                processed_path = ":".join(processed_path_segments)
                did_web_string += f":{processed_path}"
        self._did = did_web_string

        # For did:web, the key ID often includes the full DID plus a fragment.
        # Using #key-1 is a common convention, but could also be #controller or even the public key multibase.
        # For simplicity and consistency with what Ed25519VerificationKey2020 might expect as a fragment,
        # lets use a generic key-1, but a more specific one like #<publicKeyMultibase> could be used.
        self._key_id_fragment = "key-1"
        self._key_id = f"{self._did}#{self._key_id_fragment}"

        verification_method = VerificationMethodModel(
            id=self._key_id,
            type="Ed25519VerificationKey2020",
            controller=self._did,
            publicKeyMultibase=self._public_key_multibase,
        )

        self._did_document_model = DIDDocumentModel(
            context=[
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1",
            ],
            id=self._did,
            verificationMethod=[verification_method],
            authentication=[self._key_id],
            assertionMethod=[self._key_id],
        )

    @property
    def did(self) -> str:
        return self._did

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def verify_key(self) -> VerifyKey:
        return self._verify_key

    @property
    def signing_key(self) -> SigningKey:
        return self._signing_key

    @property
    def public_key_multibase(self) -> str:
        return self._public_key_multibase

    @property
    def private_key_multibase(self) -> str:
        return self._private_key_multibase

    @property
    def public_key_bytes(self) -> bytes:
        return self._public_key_bytes

    @property
    def did_document(self) -> Dict[str, Any]:
        """Returns the DID Document as a dictionary, using Pydantic model dump."""
        return self._did_document_model.model_dump(by_alias=True, exclude_none=True)

    def to_dict(self) -> Dict[str, Any]:
        """Returns key information dictionary (multibase format)."""
        return {
            "did": self._did,
            "publicKeyMultibase": self._public_key_multibase,
            "privateKeyMultibase": self._private_key_multibase,
            "key_id": self._key_id,
            "verification_method_example": self._key_id,
        }

    def to_model(self) -> DIDWebModel:
        """Returns a Pydantic model representation of the DIDWeb instance."""
        return DIDWebModel(
            did=self._did,
            did_document=self._did_document_model,
            privateKeyMultibase=self._private_key_multibase,
            publicKeyMultibase=self._public_key_multibase,
            key_id=self._key_id,
        )
