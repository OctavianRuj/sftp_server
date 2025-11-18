import json
import csv
import os
import logging
import time
from pathlib import Path

logger = logging.getLogger(__name__)

class PolicyManager:
    def __init__(self, data_dir, audit_file):
        self.data_dir = data_dir
        self.audit_file = audit_file
        self.user_roles = {}
        self.role_perms = []
        self.mac_labels = {}
        self.dac_owners = []
        self.load_policies()

    def load_policies(self):
        # Load User Roles
        with open(os.path.join(self.data_dir, 'user_roles.json'), 'r') as f:
            self.user_roles = json.load(f)
        
        # Load Role Perms
        with open(os.path.join(self.data_dir, 'role_perms.csv'), 'r') as f:
            reader = csv.DictReader(f)
            self.role_perms = list(reader)
            
        # Load MAC Labels
        with open(os.path.join(self.data_dir, 'mac_labels.json'), 'r') as f:
            self.mac_labels = json.load(f)
            
        # Load DAC Owners
        with open(os.path.join(self.data_dir, 'dac_owners.csv'), 'r') as f:
            reader = csv.DictReader(f)
            self.dac_owners = list(reader)

        logger.info("Policies loaded successfully.")

    def audit(self, user, op, path, allowed, reason):
        record = {
            'timestamp': time.time(),
            'user': user,
            'op': op,
            'path': path,
            'allowed': allowed,
            'reason': reason
        }
        with open(self.audit_file, 'a') as f:
            f.write(json.dumps(record) + '\n')

    def authorize(self, user, op, path):
        # Default deny
        allowed = False
        reason = "Default deny"

        # 1. DAC Check (Simplified for now, assumes path ownership/mode logic)
        # In a real implementation, we'd check the actual file mode. 
        # Here we check against our loaded DAC config for the path prefix.
        dac_allowed = self._check_dac(user, op, path)
        
        # 2. MAC Check
        mac_allowed = self._check_mac(user, op, path)
        
        # 3. RBAC Check
        rbac_allowed = self._check_rbac(user, op, path)

        # Composition Rule: DAC AND MAC AND RBAC
        if dac_allowed and mac_allowed and rbac_allowed:
            allowed = True
            reason = "Allowed by DAC, MAC, and RBAC"
        else:
            allowed = False
            reasons = []
            if not dac_allowed: reasons.append("DAC denied")
            if not mac_allowed: reasons.append("MAC denied")
            if not rbac_allowed: reasons.append("RBAC denied")
            reason = "; ".join(reasons)

        self.audit(user, op, path, allowed, reason)
        return allowed, reason

    def _check_dac(self, user, op, path):
        # Simplified DAC: Check if user owns the path or has group access
        # This is a placeholder. Real DAC requires checking file stats.
        # For this stage, we'll use the dac_owners.csv to simulate ownership.
        
        # Find best matching prefix
        best_match = None
        for entry in self.dac_owners:
            if path.startswith(entry['path_prefix']):
                if best_match is None or len(entry['path_prefix']) > len(best_match['path_prefix']):
                    best_match = entry
        
        if not best_match:
            # Default to root ownership if no match? Or deny?
            # Let's say if no match, it's owned by root/root 755
            owner = 'root'
            group = 'root'
            mode = 0o755
        else:
            owner = best_match['owner']
            group = best_match['group']
            mode = int(best_match['mode'], 8)

        # Check permissions
        # Owner
        if user == owner:
            return self._check_mode(mode >> 6, op)
        # Group (assume everyone in 'users' group for simplicity unless specified)
        # We need a user-group map. Let's assume a simple one or just check 'users'
        # For now, let's say if group is 'users', everyone has access.
        if group == 'users': 
             return self._check_mode((mode >> 3) & 7, op)
        
        # Other
        return self._check_mode(mode & 7, op)

    def _check_mode(self, mode_bits, op):
        # mode_bits is 3 bits: r w x
        # op mapping:
        # read/list/stat -> r (4)
        # write/create/remove -> w (2)
        # execute/traverse -> x (1)
        
        if op in ['read', 'list', 'stat', 'opendir', 'readdir']:
            return (mode_bits & 4) != 0
        if op in ['write', 'create', 'remove', 'mkdir', 'rmdir', 'put']:
            return (mode_bits & 2) != 0
        return False # Unknown op

    def _check_mac(self, user, op, path):
        # No read up, no write down
        # Levels: public < internal < confidential
        levels = {'public': 0, 'internal': 1, 'confidential': 2}
        
        user_label = self.mac_labels['users'].get(user, 'public')
        user_level = levels.get(user_label, 0)
        
        # Find resource label
        resource_label = 'public' # Default
        for prefix, label in self.mac_labels['paths'].items():
            if path.startswith(prefix):
                resource_label = label
                # Keep looking for more specific match? 
                # The dict order isn't guaranteed, so we should find longest prefix match
                # But for now let's assume the order in json or simple logic
                pass
        
        # Better longest prefix match for resource label
        best_prefix_len = -1
        for prefix, label in self.mac_labels['paths'].items():
            if path.startswith(prefix) and len(prefix) > best_prefix_len:
                resource_label = label
                best_prefix_len = len(prefix)

        resource_level = levels.get(resource_label, 0)

        if op in ['read', 'list', 'stat', 'opendir', 'readdir', 'get']:
            # Read: User level >= Resource level (No read up)
            # Actually "No read up" means you can't read HIGHER level.
            # So User Level MUST BE >= Resource Level.
            # e.g. Confidential user (2) can read Public (0) -> 2 >= 0 OK.
            # Public user (0) can read Confidential (2) -> 0 >= 2 FALSE.
            return user_level >= resource_level
        
        if op in ['write', 'create', 'remove', 'mkdir', 'rmdir', 'put']:
            # Write: User level <= Resource level (No write down)
            # e.g. Confidential user (2) can write Public (0) -> 2 <= 0 FALSE.
            # Public user (0) can write Confidential (2) -> 0 <= 2 OK.
            return user_level <= resource_level
            
        return False

    def _check_rbac(self, user, op, path):
        roles = self.user_roles.get(user, [])
        
        # Check if ANY role allows the operation
        for role in roles:
            for perm in self.role_perms:
                if perm['role'] == role:
                    # Check prefix match
                    if path.startswith(perm['prefix']):
                        # Check op permission
                        if self._check_rbac_perm(perm, op):
                            return True
        return False

    def _check_rbac_perm(self, perm, op):
        # Map op to column
        # read, write, delete, mkdir, list, stat
        if op in ['read', 'get', 'open']: return perm['read'] == '1'
        if op in ['write', 'put', 'create']: return perm['write'] == '1'
        if op in ['delete', 'remove', 'rmdir']: return perm['delete'] == '1'
        if op in ['mkdir']: return perm['mkdir'] == '1'
        if op in ['list', 'opendir', 'readdir']: return perm['list'] == '1'
        if op in ['stat', 'lstat', 'fstat']: return perm['stat'] == '1'
        return False
