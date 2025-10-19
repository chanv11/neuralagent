from passlib.context import CryptContext
import hashlib

# Create a password context with PBKDF2 (more reliable than bcrypt)
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

def _preprocess_password(password: str) -> str:
    """Pre-process password with SHA256 to ensure it's within bcrypt limits."""
    # Always use SHA256 to ensure consistent length and avoid bcrypt 72-byte limit
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def hash_password(password: str) -> str:
    """Hash a password using bcrypt with SHA256 pre-processing."""
    preprocessed = _preprocess_password(password)
    return pwd_context.hash(preprocessed)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash with SHA256 pre-processing."""
    preprocessed = _preprocess_password(plain_password)
    return pwd_context.verify(preprocessed, hashed_password)
