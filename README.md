# SFTP Secure Server Project

## Overview
This project implements a secure SFTP server with DAC, MAC, and RBAC access controls. It uses `asyncssh` for the transport layer and implements the SFTP v3 protocol logic.

## Setup and Running

### Prerequisites
- Python 3.x
- `asyncssh` library (`pip install asyncssh`)

### Installation
1. Clone the repository.
2. Install dependencies:
   ```bash
   pip install asyncssh
   ```
3. Generate host key (if not present):
   ```bash
   ssh-keygen -t ed25519 -N "" -f server/ssh_host_ed25519_key
   ```

### Running the Server
```bash
python server/server.py
```
The server listens on port 2222.

### Running the Client
```bash
python client/client.py --host 127.0.0.1 --port 2222 --username bob
```

## Access Control Design

### Enforcement Point
Authorization is checked in `server/policy.py` inside the `authorize(user, op, path)` function. This is called after path canonicalization and before any filesystem operation.

### Models
1. **DAC**: Checks ownership and mode bits. Defined in `data/dac_owners.csv`.
2. **MAC**: Enforces Bell-LaPadula (No Read Up, No Write Down). Labels defined in `data/mac_labels.json`.
3. **RBAC**: Checks role-based permissions. Defined in `data/user_roles.json` and `data/role_perms.csv`.

### Composition Rule
Final Decision = DAC AND MAC AND RBAC. All three must allow the operation.

### Auditing
All decisions are logged to `audit.jsonl`.

## Users
- **alice**: Admin, Confidential clearance. Password: `password123`
- **bob**: User, Internal clearance. Password: `password123`
- **eve**: Guest, Public clearance. Password: `password123`

## Testing
Run automated tests with `pytest`:
```bash
pytest tests/test_sftp.py
```
