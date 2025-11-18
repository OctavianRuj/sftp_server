# SFTP Server with DAC, MAC, and RBAC Access Control

A secure SFTP v3 server implementation with comprehensive access control models including Discretionary Access Control (DAC), Mandatory Access Control (MAC), and Role-Based Access Control (RBAC).

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Access Control Design](#access-control-design)
- [Installation](#installation)
- [Usage](#usage)
- [User Accounts](#user-accounts)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [CTF Challenge](#ctf-challenge)

---

## Overview

This project implements a secure File Transfer Protocol (SFTP) server that runs over SSH. It reuses `asyncssh` for the SSH transport layer and implements the SFTP v3 protocol with a three-layered access control system.

**Key Security Features:**
- Password-based authentication with scrypt hashing
- Unified authorization gate combining DAC, MAC, and RBAC
- Path canonicalization to prevent directory traversal
- Comprehensive audit logging
- Jail-based file system isolation

---

## Features

### SFTP v3 Protocol Support
- `INIT` / `VERSION` - Protocol negotiation
- `REALPATH` - Canonicalize paths
- `STAT` / `LSTAT` / `FSTAT` - Get file attributes
- `OPENDIR` / `READDIR` - List directories
- `MKDIR` - Create directories
- `OPEN` / `READ` / `WRITE` / `CLOSE` - File operations

### Client Commands
- `pwd` - Print working directory
- `ls [path]` - List directory contents
- `mkdir <path>` - Create directory
- `stat <path>` - Show file attributes
- `get <remote> [local]` - Download file
- `put <local> [remote]` - Upload file
- `quit` - Exit client

---

## Access Control Design

### Enforcement Point

Authorization checks occur in the `authorize(user, op, path)` function after:
1. Path canonicalization via `safe_join()` (prevents `..` attacks)
2. But before any filesystem operation

### Composition Rule

**ALL three models must approve: `DAC ∧ MAC ∧ RBAC`**

If any model denies the operation, the request is immediately rejected.

### Operations Mapping

| SFTP Operation | Authorization Operation | Required Permission |
|----------------|------------------------|---------------------|
| REALPATH, STAT, LSTAT, FSTAT | `stat` | Read (DAC), No read up (MAC), Role permission (RBAC) |
| OPENDIR, READDIR | `list` | Read (DAC), No read up (MAC), Role permission (RBAC) |
| OPEN(read), READ | `read` | Read (DAC), No read up (MAC), Role permission (RBAC) |
| OPEN(write), WRITE | `write` | Write (DAC), No write down (MAC), Role permission (RBAC) |
| MKDIR | `mkdir` | Write (DAC), No write down (MAC), Role permission (RBAC) |

### Default-Deny Behavior

- Unknown operations are denied
- Users without roles are denied all access
- Paths without explicit permissions use default settings
- Missing authorization data causes operation denial

---

## DAC (Discretionary Access Control)

### Model

Unix-style owner/group/other permissions with mode bits (rwx).

### Configuration

**File:** `data/dac_owner.json`

```json
{
    "path_owners": {
        "/secret_storage": {"owner": "alice", "group": "admin", "mode": "0700"},
        "/admin": {"owner": "alice", "group": "admin", "mode": "0770"},
        "/projects": {"owner": "bob", "group": "analyst", "mode": "0775"},
        "/public": {"owner": "eve", "group": "intern", "mode": "0777"}
    },
    "default": {"owner": "root", "group": "root", "mode": "0755"},
    "user_groups": {
        "alice": "admin",
        "bob": "analyst",
        "eve": "intern"
    }
}
```

### Permission Bits

- **Owner (bits 6-8):** `0700` = rwx for owner
- **Group (bits 3-5):** `0070` = rwx for group
- **Other (bits 0-2):** `0007` = rwx for others

### Enforcement

1. Determine if user is owner, group member, or other
2. Extract relevant permission bits
3. Check if required permission (read=4, write=2) is set
4. Deny if permission bit is not set

### Inheritance

New files/directories created under a path inherit the owner and group from the path configuration, with default mode `0644` for files and `0755` for directories.

### Example Outcomes

| User | Path | Operation | Owner Match | Result |
|------|------|-----------|-------------|---------|
| alice | /secret_storage/flag.txt | read | Yes (owner) | ✅ Allow (mode 0700, owner has r) |
| bob | /secret_storage/flag.txt | read | No (other) | ❌ Deny (mode 0700, other has no r) |
| alice | /admin/data.txt | read | No (but in group) | ✅ Allow (mode 0770, group has r) |
| eve | /public/readme.txt | read | No (other) | ✅ Allow (mode 0777, other has r) |

---

## MAC (Mandatory Access Control)

### Model

Bell-LaPadula model with clearance levels:
- **No Read Up:** Users can only read at or below their clearance level
- **No Write Down:** Users can only write at or above their clearance level

### Label Hierarchy

```
public (0) < internal (1) < confidential (2)
```

### Configuration

**File:** `data/mac_labels.json`

```json
{
    "labels": {
        "public": 0,
        "internal": 1,
        "confidential": 2
    },
    "user_clearances": {
        "alice": "confidential",
        "bob": "internal",
        "eve": "public"
    },
    "path_labels": {
        "/public": "public",
        "/internal": "internal",
        "/confidential": "confidential",
        "/secret_storage": "confidential",
        "/projects": "internal",
        "/admin": "confidential"
    }
}
```

### Enforcement

**Read Operations:**
```python
if resource_level <= user_clearance:
    allow  # Can read at or below clearance
else:
    deny  # No read up
```

**Write Operations:**
```python
if resource_level >= user_clearance:
    allow  # Can write at or above clearance
else:
    deny  # No write down
```

### Label Storage

Labels are stored in a mapping file and matched by path prefix (longest match wins).

### Example Outcomes

| User | Clearance | Path | Label | Operation | Result |
|------|-----------|------|-------|-----------|---------|
| alice | confidential (2) | /public/file.txt | public (0) | read | ✅ Allow (2 >= 0) |
| bob | internal (1) | /secret_storage/flag.txt | confidential (2) | read | ❌ Deny (1 < 2, no read up) |
| alice | confidential (2) | /public/leak.txt | public (0) | write | ❌ Deny (2 > 0, no write down) |
| bob | internal (1) | /projects/report.csv | internal (1) | read | ✅ Allow (1 == 1) |

---

## RBAC (Role-Based Access Control)

### Model

- Users are assigned roles
- Roles grant permissions on resources
- Union of all role permissions applies
- Explicit deny rules override allows (if implemented)

### Configuration

**User Roles** (`data/user_roles.json`):
```json
{
    "alice": ["admin"],
    "bob": ["analyst"],
    "eve": ["intern"]
}
```

**Role Permissions** (`data/role_perms.csv`):
```csv
role,resource,read,write,delete
admin,model.pkl,read,write,delete
admin,audit.log,read,write
admin,report.csv,read,write,delete
admin,secret_storage/flag.txt,read
analyst,model.pkl,read,write
analyst,audit.log,read
analyst,report.csv,read,write
intern,report.csv,read
```

### Enforcement

1. Look up user's roles from `user_roles.json`
2. For each role, check if it grants the required permission on the resource
3. Check exact matches first, then prefix matches (e.g., `projects/*`)
4. If any role grants permission, allow; otherwise deny

### Resource Scoping

- Exact match: `report.csv` matches only `/report.csv`
- Prefix match: `projects/*` matches `/projects/anything.txt`
- Partial match: `admin` matches paths containing `admin`

### Example Outcomes

| User | Roles | Resource | Permission | Result |
|------|-------|----------|------------|---------|
| alice | admin | secret_storage/flag.txt | read | ✅ Allow (admin grants read) |
| bob | analyst | secret_storage/flag.txt | read | ❌ Deny (analyst has no permission) |
| bob | analyst | model.pkl | read | ✅ Allow (analyst grants read) |
| eve | intern | report.csv | write | ❌ Deny (intern only has read) |

---

## Composite Examples

### Scenario 1: Alice reads flag

```
DAC: alice is owner of /secret_storage (mode 0700) → ✅ Allow
MAC: alice has confidential clearance, flag is confidential → ✅ Allow
RBAC: alice has admin role with read on secret_storage/flag.txt → ✅ Allow
Final: ✅ ALLOW
```

### Scenario 2: Bob tries to read flag

```
DAC: bob is not owner, not in admin group, mode 0700 → ❌ DENY
(Stops here, MAC and RBAC not checked)
Final: ❌ DENY (blocked by DAC)
```

### Scenario 3: Alice tries to write to public directory

```
DAC: alice is not owner of /public, but mode 0777 allows all → ✅ Allow
MAC: alice has confidential clearance, public is level 0 → ❌ DENY (no write down)
(Stops here, RBAC not checked)
Final: ❌ DENY (blocked by MAC)
```

### Scenario 4: Bob reads internal project file

```
DAC: bob is owner of /projects, mode 0775 → ✅ Allow
MAC: bob has internal clearance, /projects is internal → ✅ Allow
RBAC: bob has analyst role with read on project files → ✅ Allow
Final: ✅ ALLOW
```

---

## Auditing

All authorization decisions are logged to `server/audit.jsonl`:

```json
{
    "timestamp": "2025-11-18T10:23:45Z",
    "user": "alice",
    "op": "read",
    "path": "/secret_storage/flag.txt",
    "allowed": true,
    "reason": "Allowed: DAC: owner read allowed; MAC: read allowed (user=confidential, resource=confidential); RBAC: role 'admin' grants read on 'secret_storage/flag.txt'"
}
```

**Fields:**
- `timestamp`: ISO 8601 UTC timestamp
- `user`: Username attempting operation
- `op`: Operation type (read, write, stat, etc.)
- `path`: POSIX path being accessed
- `allowed`: Boolean decision
- `reason`: Detailed explanation

---

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Install Dependencies

```bash
pip install asyncssh pytest
```

### Generate Host Key

The server requires an Ed25519 host key:

```bash
ssh-keygen -t ed25519 -N '' -f server/ssh_host_ed25519_key
```

---

## Usage

### Starting the Server

```bash
python server/server.py
```

**Default settings:**
- Host: `0.0.0.0`
- Port: `8022`
- Jail root: `server/sftp_root/`

The server will:
1. Load policy data from `data/` directory
2. Create jail root if it doesn't exist
3. Listen for SSH/SFTP connections
4. Log to console and `server/audit.jsonl`

### Using the Client

```bash
python client/client.py <host> <username> <password> [port]
```

**Example:**
```bash
python client/client.py localhost alice password123 8022
```

**Interactive session:**
```
sftp> pwd
/
sftp> ls
secret_storage
Test.txt
sftp> get secret_storage/flag.txt
Downloaded: secret_storage/flag.txt -> flag.txt
sftp> quit
```

### Interoperability with OpenSSH

The server is compatible with standard SFTP clients:

```bash
sftp -P 8022 alice@localhost
```

**Note:** On first connection, verify the host key fingerprint.

---

## User Accounts

### Predefined Users

| Username | Password | Role | Clearance | Description |
|----------|----------|------|-----------|-------------|
| alice | password123 | admin | confidential | Full access to all resources including flag |
| bob | password456 | analyst | internal | Can read/write project files, no access to confidential |
| eve | password789 | intern | public | Limited read-only access to public resources |

### Password Hashing

Passwords are hashed using **scrypt** with parameters:
- N = 16384 (CPU/memory cost)
- r = 8 (block size)
- p = 1 (parallelization)
- dklen = 32 (output length)

Stored in `data/users.json` with base64-encoded salt and hash.

---

## Testing

### Running Automated Tests

```bash
# Install pytest if not already installed
pip install pytest

# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_policy.py -v

# Run specific test
pytest tests/test_policy.py::TestDAC::test_owner_can_read_own_file -v
```

### Test Coverage

**tests/test_auth.py:**
- Password verification with correct/incorrect passwords
- Malformed input handling
- Different scrypt parameters

**tests/test_policy.py:**
- **DAC Tests:** Owner, group, other permissions; directory execute bits
- **MAC Tests:** No read up, no write down, read/write at level
- **RBAC Tests:** Role permissions, union of roles, deny overrides
- **Composite Tests:** Multiple models interacting, conflict resolution
- **Audit Tests:** Verify audit records are written with correct fields

### Manual Testing

**Test 1: Alice accesses flag (should succeed)**
```bash
python client/client.py localhost alice password123 8022
sftp> get secret_storage/flag.txt
# Should download successfully
```

**Test 2: Bob tries to access flag (should fail)**
```bash
python client/client.py localhost bob password456 8022
sftp> get secret_storage/flag.txt
# Should show "Error: Permission denied"
```

**Test 3: Directory traversal blocked**
```bash
python client/client.py localhost bob password456 8022
sftp> get ../../../etc/passwd
# Should fail - path canonicalization prevents escape
```

---

## Project Structure

```
.
├── README.md                  # This file
├── CTF_writeup.md            # CTF documentation
├── server/
│   ├── server.py             # SFTP server with SSH transport
│   ├── auth.py               # Password verification (scrypt)
│   ├── policy.py             # DAC+MAC+RBAC authorization gate
│   ├── audit.jsonl           # Audit log (generated at runtime)
│   └── sftp_root/            # Jail root directory
│       ├── secret_storage/
│       │   └── flag.txt      # CTF flag
│       └── Test.txt
├── client/
│   └── client.py             # SFTP client CLI
├── data/
│   ├── users.json            # User credentials (scrypt hashes)
│   ├── user_roles.json       # User→Role mappings
│   ├── role_perms.csv        # Role→Permission matrix
│   ├── mac_labels.json       # MAC clearances and labels
│   └── dac_owner.json        # DAC ownership and modes
└── tests/
    ├── test_auth.py          # Authentication tests
    └── test_policy.py        # Authorization tests (DAC/MAC/RBAC)
```

---

## CTF Challenge

### Flag Location

**Path:** `/secret_storage/flag.txt`  
**Content:** `FLAG{access_control_is_not_optional_123}`

### Protections

The flag is protected by **two defense layers**:

1. **RBAC Layer:** Only the `admin` role can read `secret_storage/flag.txt`
   - Alice (admin) → ✅ Allowed
   - Bob (analyst), Eve (intern) → ❌ Denied

2. **Path Canonicalization:** Prevents directory traversal attacks
   - `safe_join()` resolves paths and ensures they stay within jail
   - Blocks attempts like `../../secret_storage/flag.txt`

### Attack Scenarios

See `CTF_writeup.md` for detailed attack scenarios including:
- Directory traversal attempts
- Symlink following exploits
- Handle manipulation attacks
- TOCTOU race conditions

### Accessing the Flag

Only Alice can successfully retrieve the flag:

```bash
python client/client.py localhost alice password123 8022
sftp> get secret_storage/flag.txt
Downloaded: secret_storage/flag.txt -> flag.txt
```

---

## Known Limitations

1. **TOCTOU Race Conditions:** Complete protection requires FD-based authorization
2. **No Public Key Authentication:** Only password auth is implemented
3. **Limited SFTP Commands:** Only v3 subset is implemented (no REMOVE, RENAME, etc.)
4. **Static User/Role Data:** No runtime user management
5. **Single-Server Only:** No clustering or high-availability features

---

## Security Considerations

### Strengths

✅ Defense-in-depth with three independent access control models  
✅ Comprehensive audit logging for forensics and compliance  
✅ Path canonicalization prevents traversal attacks  
✅ Jail-based isolation limits blast radius  
✅ Scrypt password hashing with proper parameters  

### Recommendations for Production

- Add rate limiting for failed authentication attempts
- Implement public key authentication
- Use a proper database for audit logs (not JSONL)
- Add TLS/SSL for defense in depth (SSH already encrypts)
- Implement role hierarchy and permission inheritance
- Add real-time alerting for suspicious access patterns

---

## License

This project is for educational purposes as part of a Computer Security course.

---

## Contributors

DSAI Computer Security Project Team - Fall 2025
