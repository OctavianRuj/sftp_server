import json
import csv
import os
import hashlib
import base64

DATA_DIR = 'data'
os.makedirs(DATA_DIR, exist_ok=True)

def hash_password(password, salt):
    # Simple sha256 for demonstration, in real app use scrypt/argon2
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return base64.b64encode(dk).decode()

users = []
for username, pwd in [('alice', 'password123'), ('bob', 'password123'), ('eve', 'password123')]:
    salt = os.urandom(16)
    salt_b64 = base64.b64encode(salt).decode()
    pwd_hash = hash_password(pwd, salt)
    users.append({
        'username': username,
        'salt': salt_b64,
        'password_hash': pwd_hash,
        'algo': 'pbkdf2_sha256',
        'iterations': 100000
    })

with open(os.path.join(DATA_DIR, 'users.json'), 'w') as f:
    json.dump(users, f, indent=2)

user_roles = {
    'alice': ['admin'],
    'bob': ['user'],
    'eve': ['guest']
}

with open(os.path.join(DATA_DIR, 'user_roles.json'), 'w') as f:
    json.dump(user_roles, f, indent=2)

# Role permissions
# role, resource_prefix, permissions...
# We'll define columns: role, prefix, read, write, delete, mkdir, list, stat
role_perms = [
    ['role', 'prefix', 'read', 'write', 'delete', 'mkdir', 'list', 'stat'],
    ['admin', '/', '1', '1', '1', '1', '1', '1'],
    ['user', '/home/bob', '1', '1', '1', '1', '1', '1'],
    ['user', '/public', '1', '0', '0', '0', '1', '1'],
    ['guest', '/public', '1', '0', '0', '0', '1', '1']
]

with open(os.path.join(DATA_DIR, 'role_perms.csv'), 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerows(role_perms)

mac_labels = {
    "users": {
        "alice": "confidential",
        "bob": "internal",
        "eve": "public"
    },
    "paths": {
        "/public": "public",
        "/internal": "internal",
        "/confidential": "confidential"
    }
}

with open(os.path.join(DATA_DIR, 'mac_labels.json'), 'w') as f:
    json.dump(mac_labels, f, indent=2)

dac_owners = [
    ['path_prefix', 'owner', 'group', 'mode'],
    ['/home/bob', 'bob', 'users', '700'],
    ['/public', 'alice', 'users', '755'],
    ['/internal', 'alice', 'admins', '770'],
    ['/confidential', 'alice', 'admins', '700']
]

with open(os.path.join(DATA_DIR, 'dac_owners.csv'), 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerows(dac_owners)

print("Data files generated successfully.")
