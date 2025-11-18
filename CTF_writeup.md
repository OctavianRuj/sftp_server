# CTF Writeup

## Flag Location
The flag is located at `/confidential/flag.txt`.
Content: `FLAG{groupXX_sftp_wins}`

## Protections
1. **MAC (Mandatory Access Control)**: The `/confidential` directory is labeled `confidential`. Only users with `confidential` clearance (like `alice`) can read from it. Users with `public` or `internal` clearance cannot read up.
2. **DAC (Discretionary Access Control)**: The directory is owned by `alice` with mode `700`. Only `alice` can access it.
3. **RBAC (Role-Based Access Control)**: Only the `admin` role has permissions to read/list `/confidential` (via root `/` inheritance).

## Attack Attempt: Directory Traversal
**Scenario**: A malicious user `eve` (guest) tries to access the flag using directory traversal.
**Command**: `get ../confidential/flag.txt` (assuming she is in `/public`) or `get /confidential/flag.txt`.

**Mitigation**:
- **Path Canonicalization**: The server resolves `..` securely using `os.path.abspath` and ensures the resulting path starts with the jail root.
- **Policy Enforcement**: Even if traversal succeeded in path resolution, the `authorize` gate checks the resolved path.
    - `eve` has `public` clearance. Accessing `/confidential` (label `confidential`) violates "No Read Up".
    - `eve` is not the owner and has no group access (DAC 700).
    - `eve`'s role `guest` does not have permissions for `/confidential` (only `/public`).

## Evidence
Audit logs show the denied attempt:
```json
{"timestamp": 1731964660.123, "user": "eve", "op": "open", "path": "/confidential/flag.txt", "allowed": false, "reason": "DAC denied; MAC denied; RBAC denied"}
```
