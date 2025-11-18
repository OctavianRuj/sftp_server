"""
policy.py

Unified DAC+MAC+RBAC authorization gate with auditing.

This module implements three access control models:
1. DAC (Discretionary Access Control) - Unix-style owner/group/other permissions
2. MAC (Mandatory Access Control) - Label-based clearance levels
3. RBAC (Role-Based Access Control) - Role-based permissions on resources

Composition Rule: ALL three models must approve (DAC ∧ MAC ∧ RBAC).
If any model denies, the operation is denied.

All authorization decisions are logged to audit.jsonl.
"""

import csv
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# Paths to policy data files
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
USERS_FILE = DATA_DIR / "users.json"
USER_ROLES_FILE = DATA_DIR / "user_roles.json"
ROLE_PERMS_FILE = DATA_DIR / "role_perms.csv"
MAC_LABELS_FILE = DATA_DIR / "mac_labels.json"
DAC_OWNERS_FILE = DATA_DIR / "dac_owner.json"
AUDIT_FILE = Path(__file__).resolve().parent / "audit.jsonl"

# Global policy data (loaded at startup)
_users: Dict = {}
_user_roles: Dict[str, List[str]] = {}
_role_perms: Dict[str, Dict[str, Set[str]]] = {}  # role -> {resource: {perms}}
_mac_data: Dict = {}
_dac_data: Dict = {}
_label_hierarchy: Dict[str, int] = {}


def load_policy_data():
    """Load all policy data files at startup."""
    global _users, _user_roles, _role_perms, _mac_data, _dac_data, _label_hierarchy
    
    # Load users
    try:
        with open(USERS_FILE, 'r') as f:
            users_list = json.load(f)
            _users = {u['username']: u for u in users_list}
        print(f"[Policy] Loaded {len(_users)} users from {USERS_FILE}")
    except Exception as e:
        raise RuntimeError(f"Failed to load users: {e}")
    
    # Load user roles
    try:
        with open(USER_ROLES_FILE, 'r') as f:
            _user_roles = json.load(f)
        print(f"[Policy] Loaded user roles from {USER_ROLES_FILE}")
    except Exception as e:
        raise RuntimeError(f"Failed to load user roles: {e}")
    
    # Load role permissions
    try:
        with open(ROLE_PERMS_FILE, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                role = row['role']
                resource = row['resource']
                perms = set()
                if row.get('read'):
                    perms.add('read')
                if row.get('write'):
                    perms.add('write')
                if row.get('delete'):
                    perms.add('delete')
                
                if role not in _role_perms:
                    _role_perms[role] = {}
                _role_perms[role][resource] = perms
        print(f"[Policy] Loaded role permissions from {ROLE_PERMS_FILE}")
    except Exception as e:
        raise RuntimeError(f"Failed to load role permissions: {e}")
    
    # Load MAC labels
    try:
        with open(MAC_LABELS_FILE, 'r') as f:
            _mac_data = json.load(f)
            _label_hierarchy = _mac_data.get('labels', {})
        print(f"[Policy] Loaded MAC labels from {MAC_LABELS_FILE}")
    except Exception as e:
        raise RuntimeError(f"Failed to load MAC labels: {e}")
    
    # Load DAC owners
    try:
        with open(DAC_OWNERS_FILE, 'r') as f:
            _dac_data = json.load(f)
        print(f"[Policy] Loaded DAC owners from {DAC_OWNERS_FILE}")
    except Exception as e:
        raise RuntimeError(f"Failed to load DAC owners: {e}")


def get_user(username: str) -> Optional[Dict]:
    """Get user data by username."""
    return _users.get(username)


def _audit_record(user: str, op: str, path: str, allowed: bool, reason: str) -> None:
    """Write an audit record to audit.jsonl."""
    rec = {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "user": user,
        "op": op,
        "path": path,
        "allowed": bool(allowed),
        "reason": reason,
    }
    try:
        with AUDIT_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
    except Exception:
        pass  # Don't block operations on audit failures


def _check_dac(user: str, op: str, path: str, jail_root: Path) -> Tuple[bool, str]:
    """
    Check Discretionary Access Control (DAC).
    
    Uses Unix-style permissions: owner/group/other with rwx bits.
    - Owner can read/write/execute their files
    - Group members get group permissions
    - Others get other permissions
    
    Operation mapping:
    - read, stat, list, realpath, lstat, fstat -> requires 'r' permission
    - write, mkdir -> requires 'w' permission
    """
    # Map operations to required permissions
    read_ops = {'read', 'stat', 'list', 'realpath', 'lstat', 'fstat', 'opendir', 'readdir'}
    write_ops = {'write', 'mkdir', 'remove', 'rename'}
    
    # Determine required permission
    if op in read_ops:
        required_perm = 'r'
    elif op in write_ops:
        required_perm = 'w'
    else:
        return False, f"DAC: Unknown operation '{op}'"
    
    # Find path configuration
    posix_path = path if path.startswith('/') else '/' + path
    path_config = None
    best_match = ""
    
    # Find the most specific path match
    for prefix, config in _dac_data.get('path_owners', {}).items():
        if posix_path.startswith(prefix) and len(prefix) > len(best_match):
            path_config = config
            best_match = prefix
    
    if not path_config:
        path_config = _dac_data.get('default', {"owner": "root", "group": "root", "mode": "0755"})
    
    owner = path_config.get('owner', 'root')
    group = path_config.get('group', 'root')
    mode_str = path_config.get('mode', '0755')
    mode = int(mode_str, 8)
    
    # Get user's group
    user_group = _dac_data.get('user_groups', {}).get(user, 'other')
    
    # Check permissions
    is_owner = (user == owner)
    is_group = (user_group == group)
    
    if is_owner:
        # Check owner permissions (bits 6-8)
        owner_perms = (mode >> 6) & 0o7
        if required_perm == 'r' and (owner_perms & 0o4):
            return True, "DAC: owner read allowed"
        elif required_perm == 'w' and (owner_perms & 0o2):
            return True, "DAC: owner write allowed"
        else:
            return False, f"DAC: owner lacks {required_perm} permission (mode={mode_str})"
    
    elif is_group:
        # Check group permissions (bits 3-5)
        group_perms = (mode >> 3) & 0o7
        if required_perm == 'r' and (group_perms & 0o4):
            return True, "DAC: group read allowed"
        elif required_perm == 'w' and (group_perms & 0o2):
            return True, "DAC: group write allowed"
        else:
            return False, f"DAC: group lacks {required_perm} permission (mode={mode_str})"
    
    else:
        # Check other permissions (bits 0-2)
        other_perms = mode & 0o7
        if required_perm == 'r' and (other_perms & 0o4):
            return True, "DAC: other read allowed"
        elif required_perm == 'w' and (other_perms & 0o2):
            return True, "DAC: other write allowed"
        else:
            return False, f"DAC: other lacks {required_perm} permission (mode={mode_str})"


def _check_mac(user: str, op: str, path: str) -> Tuple[bool, str]:
    """
    Check Mandatory Access Control (MAC).
    
    Implements Bell-LaPadula model:
    - No read up: user can only read at or below their clearance level
    - No write down: user can only write at or above their clearance level
    
    Labels: public (0) < internal (1) < confidential (2)
    """
    # Get user clearance
    user_clearance_label = _mac_data.get('user_clearances', {}).get(user, 'public')
    user_clearance = _label_hierarchy.get(user_clearance_label, 0)
    
    # Find resource label
    posix_path = path if path.startswith('/') else '/' + path
    resource_label_name = None
    best_match = ""
    
    for prefix, label in _mac_data.get('path_labels', {}).items():
        if posix_path.startswith(prefix) and len(prefix) > len(best_match):
            resource_label_name = label
            best_match = prefix
    
    if not resource_label_name:
        resource_label_name = 'public'  # Default to public
    
    resource_level = _label_hierarchy.get(resource_label_name, 0)
    
    # Map operations
    read_ops = {'read', 'stat', 'list', 'realpath', 'lstat', 'fstat', 'opendir', 'readdir'}
    write_ops = {'write', 'mkdir', 'remove', 'rename'}
    
    if op in read_ops:
        # No read up: can only read at or below clearance
        if resource_level <= user_clearance:
            return True, f"MAC: read allowed (user={user_clearance_label}, resource={resource_label_name})"
        else:
            return False, f"MAC: no read up (user clearance={user_clearance_label}, resource={resource_label_name})"
    
    elif op in write_ops:
        # No write down: can only write at or above clearance
        if resource_level >= user_clearance:
            return True, f"MAC: write allowed (user={user_clearance_label}, resource={resource_label_name})"
        else:
            return False, f"MAC: no write down (user clearance={user_clearance_label}, resource={resource_label_name})"
    
    return True, "MAC: operation not subject to MAC"


def _check_rbac(user: str, op: str, path: str) -> Tuple[bool, str]:
    """
    Check Role-Based Access Control (RBAC).
    
    - Users have roles
    - Roles grant permissions on resources
    - Union of all role permissions applies
    - Permissions are defined in role_perms.csv
    """
    # Get user's roles
    user_roles = _user_roles.get(user, [])
    if not user_roles:
        return False, f"RBAC: user '{user}' has no roles assigned"
    
    # Map operations to permission names
    op_to_perm = {
        'read': 'read',
        'stat': 'read',
        'list': 'read',
        'realpath': 'read',
        'lstat': 'read',
        'fstat': 'read',
        'opendir': 'read',
        'readdir': 'read',
        'write': 'write',
        'mkdir': 'write',
        'remove': 'delete',
        'rename': 'write',
    }
    
    required_perm = op_to_perm.get(op)
    if not required_perm:
        return False, f"RBAC: unknown operation '{op}'"
    
    # Normalize path for matching
    posix_path = path if path.startswith('/') else '/' + path
    # Remove leading slash for resource matching
    if posix_path.startswith('/'):
        resource_path = posix_path[1:]
    else:
        resource_path = posix_path
    
    # Check if any role grants the required permission
    for role in user_roles:
        role_permissions = _role_perms.get(role, {})
        
        # Check wildcard match first (most permissive)
        if '*' in role_permissions:
            if required_perm in role_permissions['*']:
                return True, f"RBAC: role '{role}' grants {required_perm} on wildcard '*'"
        
        # Check exact match
        if resource_path in role_permissions:
            if required_perm in role_permissions[resource_path]:
                return True, f"RBAC: role '{role}' grants {required_perm} on '{resource_path}'"
        
        # Check prefix matches (e.g., "projects/*" covers "projects/file.txt")
        for resource, perms in role_permissions.items():
            if resource.endswith('/*'):
                prefix = resource[:-2]
                if resource_path.startswith(prefix):
                    if required_perm in perms:
                        return True, f"RBAC: role '{role}' grants {required_perm} on prefix '{prefix}/*'"
            elif resource != '*' and '/' in resource_path and resource in resource_path:
                # Resource partial match
                if required_perm in perms:
                    return True, f"RBAC: role '{role}' grants {required_perm} on '{resource}' (matched in path)"
    
    return False, f"RBAC: no role grants {required_perm} permission for '{resource_path}'"


def authorize(user: str, op: str, path: str, jail_root: Optional[Path] = None) -> Tuple[bool, str]:
    """
    Unified authorization gate implementing DAC ∧ MAC ∧ RBAC.
    
    Args:
        user: Username attempting the operation
        op: Operation being attempted (read, write, stat, list, mkdir, etc.)
        path: POSIX-style path (rooted at jail)
        jail_root: Optional jail root path for DAC filesystem checks
    
    Returns:
        (allowed: bool, reason: str)
    
    Composition Rule: ALL three models must approve.
    If any model denies, the operation is denied.
    """
    if jail_root is None:
        jail_root = Path(__file__).resolve().parent / "sftp_root"
    
    # Check DAC
    dac_allowed, dac_reason = _check_dac(user, op, path, jail_root)
    if not dac_allowed:
        _audit_record(user, op, path, False, dac_reason)
        return False, dac_reason
    
    # Check MAC
    mac_allowed, mac_reason = _check_mac(user, op, path)
    if not mac_allowed:
        _audit_record(user, op, path, False, mac_reason)
        return False, mac_reason
    
    # Check RBAC
    rbac_allowed, rbac_reason = _check_rbac(user, op, path)
    if not rbac_allowed:
        _audit_record(user, op, path, False, rbac_reason)
        return False, rbac_reason
    
    # All checks passed
    final_reason = f"Allowed: {dac_reason}; {mac_reason}; {rbac_reason}"
    _audit_record(user, op, path, True, final_reason)
    return True, final_reason
