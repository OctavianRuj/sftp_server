# tests/test_authenticate.py
import base64
import os
import hashlib
import pytest

# Import your functions from authenticate.py
from server.auth import (
    scrypt_hash, verify_password, SCRYPT_N, SCRYPT_R, SCRYPT_P, DKLEN
)
def _mk_hash(password: str, *, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=DKLEN):
    """Return (salt_b64, hash_b64) for a freshly generated random salt."""
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=dklen)
    return base64.b64encode(salt).decode("ascii"), base64.b64encode(digest).decode("ascii")


def test_success_correct_password_default_params():
    salt_b64, hash_b64 = _mk_hash("correcthorsebatterystaple")
    assert verify_password("correcthorsebatterystaple", salt_b64, hash_b64)


def test_fail_wrong_password():
    salt_b64, hash_b64 = _mk_hash("secret123")
    assert not verify_password("not-the-same", salt_b64, hash_b64)


def test_fail_unknown_user_style_inputs_with_malformed_salt():
    # Malformed base64 for salt (simulate broken users.json entry)
    bad_salt_b64 = "###not-base64###"
    # Provide any valid-looking hash so we isolate the salt error path
    _, hash_b64 = _mk_hash("pw")
    assert not verify_password("pw", bad_salt_b64, hash_b64)


def test_fail_unknown_user_style_inputs_with_malformed_hash():
    salt_b64, _ = _mk_hash("pw")
    bad_hash_b64 = "###not-base64###"
    assert not verify_password("pw", salt_b64, bad_hash_b64)


def test_fail_when_params_mismatch():
    # Create hash with slightly different params (less memory)
    salt = os.urandom(16)
    n2, r2, p2, dk2 = SCRYPT_N // 2, SCRYPT_R, SCRYPT_P, DKLEN  # 8192 if default is 16384
    digest = hashlib.scrypt("pw".encode(), salt=salt, n=n2, r=r2, p=p2, dklen=dk2)

    salt_b64 = base64.b64encode(salt).decode()
    hash_b64 = base64.b64encode(digest).decode()

    # Verifying with DEFAULT params should fail (mismatch)
    assert not verify_password("pw", salt_b64, hash_b64)

    # Verifying with the SAME params should pass
    assert verify_password("pw", salt_b64, hash_b64, n=n2, r=r2, p=p2, dklen=dk2)

    # Verifying with DEFAULT params should fail (params mismatch)
    assert not verify_password("pw", salt_b64, hash_b64)

    # Verifying with the SAME params used for hashing should pass
    assert verify_password("pw", salt_b64, hash_b64, n=n2, r=r2, p=p2, dklen=dk2)


@pytest.mark.parametrize("pwd", ["", "a", " " * 10, "pässwörd✓"])  # empty, tiny, spaces, unicode
def test_various_password_edge_cases(pwd):
    salt_b64, hash_b64 = _mk_hash(pwd)
    assert verify_password(pwd, salt_b64, hash_b64)
    # A different value should fail
    assert not verify_password(pwd + "x", salt_b64, hash_b64)


def test_scrypt_hash_returns_bytes_and_matches_verify():
    salt = os.urandom(16)
    salt_b64 = base64.b64encode(salt).decode()
    computed = scrypt_hash("pw", salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=DKLEN)
    assert isinstance(computed, (bytes, bytearray))

    # Cross-check with verify_password
    hash_b64 = base64.b64encode(computed).decode()
    assert verify_password("pw", salt_b64, hash_b64)


def test_long_password():
    long_pw = "x" * 10000
    salt_b64, hash_b64 = _mk_hash(long_pw)
    assert verify_password(long_pw, salt_b64, hash_b64)
    assert not verify_password(long_pw[:-1], salt_b64, hash_b64)