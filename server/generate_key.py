#!/usr/bin/env python3
"""Generate an unencrypted Ed25519 SSH key for the SFTP server."""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend

# Generate Ed25519 private key
private_key = ed25519.Ed25519PrivateKey.generate()

# Serialize private key WITHOUT encryption
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.OpenSSH,
    encryption_algorithm=serialization.NoEncryption()  # NO PASSPHRASE
)

# Serialize public key
public_key = private_key.public_key()
public_openssh = public_key.public_bytes(
    encoding=serialization.Encoding.OpenSSH,
    format=serialization.PublicFormat.OpenSSH
)

# Write keys to files
with open("ssh_host_ed25519_key", "wb") as f:
    f.write(private_pem)

with open("ssh_host_ed25519_key.pub", "wb") as f:
    f.write(public_openssh)
    f.write(b" sftp-server\n")

print("Generated unencrypted Ed25519 key pair:")
print("  - ssh_host_ed25519_key")
print("  - ssh_host_ed25519_key.pub")
