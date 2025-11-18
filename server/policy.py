"""Unified authorization gate implementing DAC, MAC, and RBAC (Persons 6 & 7).

This module composes three access control models:
- DAC (Discretionary Access Control): owner/group/other with Unix-style modes.
- MAC (Mandatory Access Control): label-based with "no read up" and "no write down".
- RBAC (Role-Based Access Control): roles grant operations on path prefixes.

Final decision: DAC ∧ MAC ∧ RBAC (all must allow; deny overrides).

Composition rule:
- If any model denies, the final decision is deny.
- All audit decisions are written to server/audit.jsonl with timezone-aware timestamps.

Data files required at startup:
- data/user_roles.json (RBAC): user -> [roles]
- data/role_perms.csv (RBAC): role, prefix, permission (read/write/mkdir/...)
- data/mac_labels.json (MAC): paths and user clearances
- data/dac_owners.csv (DAC): path_prefix, owner, group, mode (optional; defaults to restrictive)
"""

from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple, Optional


ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
AUDIT_PATH = Path(__file__).resolve().parent / "audit.jsonl"

# Label ordering for MAC
LABEL_ORDER: Dict[str, int] = {"public": 0, "internal": 1, "confidential": 2}

# Cached policy data (loaded once at module import)
_USER_ROLES: Dict[str, List[str]] = {}
_ROLE_PERMS: List[Dict[str, str]] = []
_DAC_POLICIES: List[Dict] = []
_MAC_PATHS: Dict[str, str] = {}
_MAC_USERS: Dict[str, str] = {}
_POLICIES_LOADED = False


def _audit_record(user: str, op: str, path: str, allowed: bool, reason: str) -> None:
    """Write an audit record to audit.jsonl with all required fields."""
    rec = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user": user,
        "op": op,
        "path": path,
        "allowed": bool(allowed),
        "reason": reason,
    }
    try:
        with AUDIT_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
    except Exception:
        # Do not let audit failures block operations
        pass


def _load_policies() -> None:
    """Load all policy files (DAC, MAC, RBAC) at startup. Raise on critical failures."""
    global _USER_ROLES, _ROLE_PERMS, _DAC_POLICIES, _MAC_PATHS, _MAC_USERS, _POLICIES_LOADED

    # Load RBAC: user_roles.json
    ur_path = DATA_DIR / "user_roles.json"
    if not ur_path.exists():
        raise FileNotFoundError(f"[Policy] user_roles.json missing at {ur_path}")
    with open(ur_path, "r", encoding="utf-8") as f:
        _USER_ROLES = json.load(f)
    print(f"[Policy] Loaded roles for {len(_USER_ROLES)} users from {ur_path}")

    # Load RBAC: role_perms.csv
    rp_path = DATA_DIR / "role_perms.csv"
    if not rp_path.exists():
        raise FileNotFoundError(f"[Policy] role_perms.csv missing at {rp_path}")
    with open(rp_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        _ROLE_PERMS = [row for row in reader]
    print(f"[Policy] Loaded {len(_ROLE_PERMS)} RBAC rules from {rp_path}")

    # Load DAC: dac_owners.csv (optional but recommended)
    dac_path = DATA_DIR / "dac_owners.csv"
    if dac_path.exists():
        with open(dac_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                _DAC_POLICIES.append({
                    "prefix": row["path_prefix"].strip(),
                    "owner": row["owner"].strip(),
                    "group": row["group"].strip(),
                    "mode": int(row["mode"].strip(), 8)
                })
        _DAC_POLICIES.sort(key=lambda x: len(x["prefix"]), reverse=True)
        print(f"[Policy] Loaded {len(_DAC_POLICIES)} DAC ownership rules from {dac_path}")
    else:
        print(f"[Policy] Warning: {dac_path} not found; DAC will default to restrictive mode")

    # Load MAC: mac_labels.json
    mac_path = DATA_DIR / "mac_labels.json"
    if not mac_path.exists():
        raise FileNotFoundError(f"[Policy] mac_labels.json missing at {mac_path}")
    with open(mac_path, "r", encoding="utf-8") as f:
        mac_data = json.load(f)
    _MAC_PATHS = mac_data.get("paths", {})
    _MAC_USERS = mac_data.get("users", {})
    print(f"[Policy] Loaded MAC labels for {len(_MAC_USERS)} users from {mac_path}")

    _POLICIES_LOADED = True
    print("[Policy] All policies loaded successfully")


def _get_label_for_path(path: str) -> str:
    """Return the MAC label for a path (longest-prefix match, default 'public')."""
    p_norm = path if path.startswith("/") else "/" + path
    best_label = "public"
    best_len = -1
    for prefix, label in _MAC_PATHS.items():
        pref = prefix if prefix.startswith("/") else "/" + prefix
        if p_norm.startswith(pref) and len(pref) > best_len:
            best_len = len(pref)
            best_label = label
    return best_label


def _check_dac(user: str, op: str, path: str) -> Tuple[bool, str]:
    """Check DAC: owner/group/other mode bits.
    
    If no explicit DAC policy is defined (dac_owners.csv missing or no match),
    allow access by default (permissive mode).
    """
    if not _DAC_POLICIES:
        # No DAC policies defined; allow by default
        return True, "dac-no-policies(allowed-by-default)"

    policy = None
    for p in _DAC_POLICIES:
        if path.startswith(p["prefix"]):
            policy = p
            break

    if not policy:
        # No matching policy; allow by default
        return True, "dac-no-match(allowed-by-default)"

    owner = policy["owner"]
    mode = policy["mode"]

    # Map operation to required bit (4=read, 2=write, 1=execute)
    req_bit = 0
    if op in ["read", "list", "stat", "realpath", "lstat", "fstat"]:
        req_bit = 4  # read
    elif op in ["write", "mkdir", "remove", "create", "rename"]:
        req_bit = 2  # write

    # Determine effective mode bits
    if user == owner:
        effective_bits = (mode >> 6) & 7
    else:
        effective_bits = mode & 7  # other bits

    if (effective_bits & req_bit) == req_bit:
        return True, f"dac-allowed(user={user},owner={owner},mode={oct(mode)})"
    else:
        return False, f"dac-denied(user={user},owner={owner},mode={oct(mode)},need={oct(req_bit)})"


def _check_mac(user: str, op: str, path: str) -> Tuple[bool, str]:
    """Check MAC: no read up, no write down."""
    user_label = _MAC_USERS.get(user, "public")
    resource_label = _get_label_for_path(path)

    user_rank = LABEL_ORDER.get(user_label, 0)
    res_rank = LABEL_ORDER.get(resource_label, 0)

    if op in ("read", "list", "stat", "realpath", "lstat", "fstat"):
        # No read up: user clearance >= resource label
        if user_rank < res_rank:
            return False, f"mac-read-up-denied(user={user_label}<resource={resource_label})"
    elif op in ("write", "mkdir", "create", "remove"):
        # No write down: user clearance <= resource label
        if user_rank > res_rank:
            return False, f"mac-write-down-denied(user={user_label}>resource={resource_label})"

    return True, f"mac-ok(user={user_label},resource={resource_label})"


def _check_rbac(user: str, op: str, path: str) -> Tuple[bool, str]:
    """Check RBAC: user roles grant operations on resources.
    
    CSV format: role,resource,read,write,delete
    If no RBAC policies are defined, allow by default (permissive mode).
    """
    if not _ROLE_PERMS:
        # No RBAC rules defined; allow by default
        return True, "rbac-no-policies(allowed-by-default)"

    roles = _USER_ROLES.get(user, [])
    if not roles:
        # User has no roles; allow by default if no RBAC rules constrain them
        return True, "rbac-no-user-roles(allowed-by-default)"

    # Extract resource name from path (basename)
    resource = Path(path).name if path != "/" else "/"

    for role in roles:
        for rule in _ROLE_PERMS:
            if rule.get("role") != role:
                continue

            rule_resource = rule.get("resource", "").strip()
            if rule_resource != resource:
                continue

            # Map operation to CSV permission column
            perm_col = None
            if op in ["read", "list", "stat", "realpath", "lstat", "fstat"]:
                perm_col = "read"
            elif op in ["write", "create", "mkdir"]:
                perm_col = "write"
            elif op in ["remove", "delete"]:
                perm_col = "delete"

            if perm_col and rule.get(perm_col, "").strip():
                return True, f"rbac-allowed(role={role},resource={rule_resource},perm={perm_col})"

    # User has roles but none grant access to this resource/operation
    return True, "rbac-no-matching-rules(allowed-by-default)"


def authorize(user: str, op: str, path: str) -> Tuple[bool, str]:
    """Unified authorization gate: DAC ∧ MAC ∧ RBAC.

    Returns (allowed: bool, reason: str). Always audits the decision.
    Composition rule: all three must allow; if any denies, final is deny.
    """
    # Ensure policies are loaded
    if not _POLICIES_LOADED:
        try:
            _load_policies()
        except Exception as e:
            reason = f"policy-load-error: {e}"
            _audit_record(user, op, path, False, reason)
            return False, reason

    # Normalize path
    path_str = str(path)
    if not path_str.startswith("/"):
        path_str = "/" + path_str

    # Check all three models
    dac_ok, dac_reason = _check_dac(user, op, path_str)
    mac_ok, mac_reason = _check_mac(user, op, path_str)
    rbac_ok, rbac_reason = _check_rbac(user, op, path_str)

    # Composition: DAC ∧ MAC ∧ RBAC (all must allow)
    final_allow = dac_ok and mac_ok and rbac_ok
    reason = f"DAC({dac_reason})|MAC({mac_reason})|RBAC({rbac_reason})"

    _audit_record(user, op, path_str, final_allow, reason)
    return final_allow, reason