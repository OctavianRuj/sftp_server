# authenticate.py
import base64
import hashlib
import secrets
from typing import Optional

# Default scrypt parameters (these should match the ones used when the hashes
# in users.json were generated)
SCRYPT_N = 16384
SCRYPT_R = 8
SCRYPT_P = 1
DKLEN = 32


def scrypt_hash(
    password: str,
    salt: bytes,
    n: int = SCRYPT_N,
    r: int = SCRYPT_R,
    p: int = SCRYPT_P,
    dklen: int = DKLEN,
) -> bytes:
    """
    Compute the scrypt hash for a given password and salt.

    Returns the raw hash as bytes.
    """
    return hashlib.scrypt(
        password.encode("utf-8"),  # string -> bytes using UTF-8
        salt=salt,
        n=n,
        r=r,
        p=p,
        dklen=dklen,
    )


def verify_password(
    input_pw: str,
    stored_salt_b64: str,
    stored_hash_b64: str,
    n: int = SCRYPT_N,
    r: int = SCRYPT_R,
    p: int = SCRYPT_P,
    dklen: int = DKLEN,
) -> bool:
    """
    Return True iff input_pw matches the stored hash.

    - stored_salt_b64 and stored_hash_b64 are base64-encoded strings.
    - Uses constant-time comparison via secrets.compare_digest.
    """
    try:
        # 1. Decode base64-encoded salt and hash into raw bytes
        salt = base64.b64decode(stored_salt_b64)
        stored_hash = base64.b64decode(stored_hash_b64)
    except (TypeError, ValueError):
        # Malformed base64 input → treat as invalid credentials
        return False

    # 2. Compute scrypt hash of the input password with the same parameters
    computed_hash = scrypt_hash(
        input_pw,
        salt,
        n=n,
        r=r,
        p=p,
        dklen=dklen,
    )

    # 3. Compare in constant time to avoid timing attacks
    return secrets.compare_digest(computed_hash, stored_hash)