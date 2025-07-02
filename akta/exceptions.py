class AktaError(Exception):
    """Base class for exceptions in the Akta library."""
    pass

class DIDResolutionError(AktaError):
    """Raised when a DID cannot be resolved."""
    pass

class SignatureError(AktaError):
    """Raised when there is an error with a cryptographic signature."""
    pass

class NormalizationError(AktaError):
    """Raised when there is an error during data normalization."""
    pass

class VCValidationError(AktaError):
    """Raised when a Verifiable Credential fails validation."""
    pass 