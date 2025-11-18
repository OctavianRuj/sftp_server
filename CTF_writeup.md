# SFTP Server - Capture The Flag (CTF) Write-up

## Flag Information

**Flag Location:** `/secret_storage/flag.txt`  
**Flag Content:** `FLAG{access_control_is_not_optional_123}`

---

## Defense Architecture: Two-Layer Security Model

This CTF implements a **defense-in-depth** approach with two distinct security layers protecting the flag from unauthorized access.

### Layer 1: Role-Based Access Control (RBAC) - Primary Lock

**Implementation:**
- The flag is protected by RBAC permissions defined in `data/role_perms.csv`
- Only users with the `admin` role are granted `read` permission on `secret_storage/flag.txt`
- User role assignments are defined in `data/user_roles.json`

**User Roles:**
- **Alice**: `admin` role → CAN access the flag
- **Bob**: `analyst` role → NO permission for secret_storage
- **Eve**: `intern` role → NO permission for secret_storage

**Configuration:**
```csv
role,resource,read,write,delete
admin,secret_storage/flag.txt,read
```

**Why This Works:**
If Bob or Eve tries to read the flag, the `authorize()` function checks their roles against the permission matrix. Since neither `analyst` nor `intern` roles have any entry granting access to `secret_storage/flag.txt`, the request is denied with:
```
RBAC: no role grants read permission for 'secret_storage/flag.txt'
```

---

### Layer 2: Mandatory Access Control (MAC) - Secondary Lock

**Implementation:**
- MAC labels are applied to paths and users based on clearance levels
- Implements Bell-LaPadula model with "no read up" and "no write down" policies
- Labels hierarchy: `public (0) < internal (1) < confidential (2)`

**Configuration (`data/mac_labels.json`):**
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
        "/secret_storage": "confidential"
    }
}
```

**Why This Works:**
- Bob has `internal` clearance (level 1)
- `/secret_storage` is labeled `confidential` (level 2)
- MAC enforces "no read up": Bob cannot read resources above his clearance
- Eve has `public` clearance (level 0), so she also cannot read `confidential` resources

Even if Bob somehow obtained RBAC permissions, MAC would still block him:
```
MAC: no read up (user clearance=internal, resource=confidential)
```

---

### Layer 3 (Bonus): Discretionary Access Control (DAC)

**Implementation:**
- Unix-style owner/group/other permissions
- `/secret_storage` has mode `0700` (owner-only read/write/execute)
- Owner is `alice`, group is `admin`

**Configuration (`data/dac_owner.json`):**
```json
{
    "path_owners": {
        "/secret_storage": {
            "owner": "alice",
            "group": "admin",
            "mode": "0700"
        }
    },
    "user_groups": {
        "alice": "admin",
        "bob": "analyst",
        "eve": "intern"
    }
}
```

**Why This Works:**
- Mode `0700` means only the owner (alice) has read permission
- Bob and Eve are not the owner and not in the admin group
- DAC blocks them even before RBAC or MAC checks run

---

## Composition Rule: Defense-in-Depth

The `authorize()` function implements a **conjunction** of all three models:

```
Final Decision = DAC ∧ MAC ∧ RBAC
```

**This means:**
- ALL three models must approve for access to be granted
- If ANY model denies, the request is denied immediately
- The first denial short-circuits further checks

**Example Decision Flow for Bob:**
1. **DAC Check**: Bob is not owner of `/secret_storage` and mode is `0700` → ❌ DENIED
2. Authorization stops here, audit record written
3. (MAC and RBAC would also deny if checked)

---

## Attack Scenarios and Mitigations

### Attack 1: Directory Traversal

**Naive Design Vulnerability:**
A poorly implemented SFTP server might accept paths like:
```
get /public/../../secret_storage/flag.txt
```

This could escape the intended directory structure and access protected files.

**Our Mitigation:**
The `safe_join()` function in `server.py` (lines 115-150) performs **path canonicalization**:

```python
def safe_join(jail_root: Path, sftp_path: str) -> Path:
    candidate = (jail_root / sftp_path).resolve()
    jail_root_resolved = jail_root.resolve()
    candidate.relative_to(jail_root_resolved)  # Raises ValueError if outside jail
    return candidate
```

**How It Blocks the Attack:**
1. Client sends: `get ../../../secret_storage/flag.txt`
2. `safe_join()` resolves the path to absolute form
3. Checks if resolved path is under `jail_root`
4. If the path escapes the jail → `ValueError` → `STATUS(PERMISSION_DENIED)`
5. Even if traversal succeeds, authorization still applies

**Test Evidence:**
```bash
sftp> get ../../secret_storage/flag.txt
Error: Permission denied
```

**Audit Log Entry:**
```json
{
    "timestamp": "2025-11-18T10:23:45Z",
    "user": "bob",
    "op": "read",
    "path": "/secret_storage/flag.txt",
    "allowed": false,
    "reason": "DAC: other lacks r permission (mode=0700)"
}
```

---

### Attack 2: Symlink Following

**Naive Design Vulnerability:**
An attacker might create a symlink in a public directory pointing to the flag:
```bash
ln -s /secret_storage/flag.txt /public/innocent_link
get /public/innocent_link
```

**Our Mitigation:**
1. **Path Canonicalization**: `.resolve()` in `safe_join()` follows symlinks and checks the final target
2. **Authorization on Real Path**: The `authorize()` function receives the resolved, canonical path
3. Even if symlink points to `/secret_storage/flag.txt`, authorization checks apply to that path

**How It Blocks the Attack:**
1. Client requests: `/public/innocent_link`
2. Server resolves symlink to `/secret_storage/flag.txt`
3. `authorize("bob", "read", "/secret_storage/flag.txt")` is called
4. DAC/MAC/RBAC checks apply to the real file
5. Bob is denied

---

### Attack 3: Handle Reuse/Manipulation

**Naive Design Vulnerability:**
The server maintains a handle table mapping handle IDs to open files/directories. A naive implementation might:
- Not validate handles properly
- Allow one user to guess/reuse another user's handles
- Not check permissions on `FSTAT` operations

**Our Mitigation:**
The server's handle management (lines 200-220) includes:
1. **UUID-based Handle IDs**: Handles are generated using UUIDs, making them unpredictable
2. **Per-Connection Handle Tables**: Each SFTP session has its own handle table
3. **Permission Checks on Every Operation**: `FSTAT`, `READ`, `READDIR` all re-check authorization

**Example from server.py:**
```python
async def handle_fstat(self, req_id: int, handle: bytes):
    handle_id = handle.decode('utf-8', errors='ignore')
    if handle_id not in self._handles:
        await self._send_status(req_id, SSH_FX_FAILURE, "Invalid handle")
        return
    
    # Still check authorization even with valid handle
    path = self._handles[handle_id]['path']
    allowed, reason = authorize(self._username, 'fstat', path)
    if not allowed:
        await self._send_status(req_id, SSH_FX_PERMISSION_DENIED, reason)
        return
```

---

### Attack 4: Race Conditions (Time-of-Check-Time-of-Use)

**Naive Design Vulnerability:**
A TOCTOU attack might exploit timing between authorization check and file access:
1. Check permissions on `/public/file.txt` → allowed
2. Attacker swaps file with symlink to `/secret_storage/flag.txt`
3. Server reads from symlink → exposes flag

**Our Mitigation:**
1. **Authorization After Canonicalization**: We call `authorize()` after `safe_join()` resolves paths
2. **Atomic Operations**: File operations use Python's atomic file APIs
3. **Re-validation**: Some operations re-check authorization even after handle creation

**Limitation:**
Complete TOCTOU protection requires file descriptor-based authorization, which is beyond the scope of this project. Our mitigation reduces but doesn't eliminate this attack surface.

---

## Auditing and Detection

Every authorization decision is logged to `server/audit.jsonl` with the following fields:

```json
{
    "timestamp": "2025-11-18T10:45:32Z",
    "user": "bob",
    "op": "read",
    "path": "/secret_storage/flag.txt",
    "allowed": false,
    "reason": "DAC: other lacks r permission (mode=0700)"
}
```

**Detection Capabilities:**
1. **Failed Access Attempts**: Any denied request is logged with the denial reason
2. **Unusual Access Patterns**: Multiple failed attempts from same user can trigger alerts
3. **Successful Flag Access**: When Alice accesses the flag, it's logged for compliance
4. **Attack Attribution**: Username and path reveal who tried to access what

**Example Audit Query:**
```python
# Find all attempts to access the flag
with open('server/audit.jsonl') as f:
    for line in f:
        record = json.loads(line)
        if 'secret_storage/flag.txt' in record['path']:
            print(f"{record['timestamp']}: {record['user']} - {record['allowed']}")
```

---

## Testing Evidence

**Test 1: Alice Can Access Flag**
```bash
$ python client/client.py localhost alice password123 8022
sftp> get secret_storage/flag.txt
Downloaded: secret_storage/flag.txt -> flag.txt
$ cat flag.txt
FLAG{access_control_is_not_optional_123}
```

**Test 2: Bob Cannot Access Flag (RBAC Denial)**
```bash
$ python client/client.py localhost bob password456 8022
sftp> get secret_storage/flag.txt
Error: Permission denied
```

**Audit Log:**
```json
{"timestamp": "2025-11-18T11:02:15Z", "user": "bob", "op": "read", 
 "path": "/secret_storage/flag.txt", "allowed": false, 
 "reason": "DAC: other lacks r permission (mode=0700)"}
```

**Test 3: Eve Cannot Access Flag**
```bash
$ python client/client.py localhost eve password789 8022
sftp> get secret_storage/flag.txt
Error: Permission denied
```

**Test 4: Directory Traversal Blocked**
```bash
$ python client/client.py localhost bob password456 8022
sftp> get ../secret_storage/flag.txt
Error: Permission denied
```

---

## Conclusion

This CTF demonstrates a comprehensive defense-in-depth approach to access control:

1. **RBAC** provides role-based permissions enforcing business logic
2. **MAC** enforces information flow policies based on clearance levels
3. **DAC** provides traditional Unix-style ownership controls
4. **Path Canonicalization** prevents directory traversal attacks
5. **Comprehensive Auditing** enables detection and forensics

The flag is protected by multiple independent security layers, requiring an attacker to defeat all of them simultaneously—a significantly harder challenge than bypassing a single control.

**Key Takeaway:** *Access control is not optional. Defense-in-depth with multiple, independent security layers provides robust protection against a variety of attack vectors.*
