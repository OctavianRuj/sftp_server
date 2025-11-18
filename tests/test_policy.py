"""
Test authorization policies (DAC, MAC, RBAC) for SFTP server.

Tests each access control model independently and in composition.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'server'))

import pytest
from pathlib import Path
from policy import authorize, load_policy_data, _check_dac, _check_mac, _check_rbac


@pytest.fixture(scope="module", autouse=True)
def setup_policy():
    """Load policy data once for all tests."""
    load_policy_data()


class TestDAC:
    """Test Discretionary Access Control (DAC)."""
    
    def test_owner_can_read_own_file(self):
        """Objective: Owner (alice) can read files in /secret_storage (mode 0700)."""
        jail_root = Path(__file__).parent.parent / "server" / "sftp_root"
        allowed, reason = _check_dac("alice", "read", "/secret_storage/flag.txt", jail_root)
        assert allowed, f"Owner should be able to read their file: {reason}"
    
    def test_owner_can_write_own_file(self):
        """Objective: Owner (alice) can write files in /secret_storage (mode 0700)."""
        jail_root = Path(__file__).parent.parent / "server" / "sftp_root"
        allowed, reason = _check_dac("alice", "write", "/secret_storage/flag.txt", jail_root)
        assert allowed, f"Owner should be able to write their file: {reason}"
    
    def test_other_cannot_read_owner_file(self):
        """Objective: Other users (bob) cannot read alice's files (mode 0700)."""
        jail_root = Path(__file__).parent.parent / "server" / "sftp_root"
        allowed, reason = _check_dac("bob", "read", "/secret_storage/flag.txt", jail_root)
        assert not allowed, "Other users should not be able to read owner-only files"
    
    def test_group_can_read_group_file(self):
        """Objective: Group members can read group-readable files (mode 0770)."""
        jail_root = Path(__file__).parent.parent / "server" / "sftp_root"
        # Alice is in admin group, /admin has mode 0770
        allowed, reason = _check_dac("alice", "read", "/admin/data.txt", jail_root)
        assert allowed, f"Group member should be able to read group file: {reason}"
    
    def test_public_can_read_public_file(self):
        """Objective: Anyone can read public files (mode 0777)."""
        jail_root = Path(__file__).parent.parent / "server" / "sftp_root"
        allowed, reason = _check_dac("eve", "read", "/public/readme.txt", jail_root)
        assert allowed, f"Public files should be readable by all: {reason}"


class TestMAC:
    """Test Mandatory Access Control (MAC)."""
    
    def test_no_read_up_confidential(self):
        """Objective: User with 'internal' clearance cannot read 'confidential' files."""
        # Bob has 'internal' clearance, /secret_storage is 'confidential'
        allowed, reason = _check_mac("bob", "read", "/secret_storage/flag.txt")
        assert not allowed, "No read up: internal cannot read confidential"
    
    def test_can_read_at_level(self):
        """Objective: User can read files at their clearance level."""
        # Bob has 'internal' clearance, /internal is 'internal'
        allowed, reason = _check_mac("bob", "read", "/internal/report.csv")
        assert allowed, f"User can read at their clearance level: {reason}"
    
    def test_can_read_below_level(self):
        """Objective: User can read files below their clearance level."""
        # Alice has 'confidential' clearance, /public is 'public'
        allowed, reason = _check_mac("alice", "read", "/public/readme.txt")
        assert allowed, f"User can read below their clearance: {reason}"
    
    def test_no_write_down(self):
        """Objective: Confidential user cannot write to public directory."""
        # Alice has 'confidential' clearance, /public is 'public'
        allowed, reason = _check_mac("alice", "write", "/public/leak.txt")
        assert not allowed, "No write down: confidential cannot write to public"
    
    def test_can_write_at_level(self):
        """Objective: User can write at their clearance level."""
        # Bob has 'internal' clearance, /internal is 'internal'
        allowed, reason = _check_mac("bob", "write", "/internal/newfile.txt")
        assert allowed, f"User can write at their level: {reason}"


class TestRBAC:
    """Test Role-Based Access Control (RBAC)."""
    
    def test_admin_can_read_flag(self):
        """Objective: Admin role can read secret_storage/flag.txt."""
        # Alice has 'admin' role, which grants read on secret_storage/flag.txt
        allowed, reason = _check_rbac("alice", "read", "/secret_storage/flag.txt")
        assert allowed, f"Admin should be able to read flag: {reason}"
    
    def test_analyst_cannot_read_flag(self):
        """Objective: Analyst role cannot read secret_storage/flag.txt (no permission)."""
        # Bob has 'analyst' role, no permission for secret_storage
        allowed, reason = _check_rbac("bob", "read", "/secret_storage/flag.txt")
        assert not allowed, "Analyst should not have permission for flag"
    
    def test_analyst_can_read_model(self):
        """Objective: Analyst can read model.pkl."""
        # Bob has 'analyst' role, which grants read on model.pkl
        allowed, reason = _check_rbac("bob", "read", "/model.pkl")
        assert allowed, f"Analyst should be able to read model.pkl: {reason}"
    
    def test_analyst_can_write_model(self):
        """Objective: Analyst can write model.pkl."""
        # Bob has 'analyst' role, which grants write on model.pkl
        allowed, reason = _check_rbac("bob", "write", "/model.pkl")
        assert allowed, f"Analyst should be able to write model.pkl: {reason}"
    
    def test_intern_can_only_read_report(self):
        """Objective: Intern can read but not write report.csv."""
        # Eve has 'intern' role, which grants only read on report.csv
        allowed_read, _ = _check_rbac("eve", "read", "/report.csv")
        allowed_write, reason = _check_rbac("eve", "write", "/report.csv")
        assert allowed_read, "Intern should be able to read report.csv"
        assert not allowed_write, "Intern should not be able to write report.csv"


class TestComposite:
    """Test composite authorization (DAC ∧ MAC ∧ RBAC)."""
    
    def test_alice_can_access_flag(self):
        """Objective: Alice passes all three checks for flag access."""
        # Alice: owner (DAC), confidential clearance (MAC), admin role (RBAC)
        jail_root = Path(__file__).parent.parent / "server" / "sftp_root"
        allowed, reason = authorize("alice", "read", "/secret_storage/flag.txt", jail_root)
        assert allowed, f"Alice should pass all checks: {reason}"
    
    def test_bob_blocked_by_multiple_models(self):
        """Objective: Bob fails multiple checks (DAC, MAC, RBAC)."""
        jail_root = Path(__file__).parent.parent / "server" / "sftp_root"
        allowed, reason = authorize("bob", "read", "/secret_storage/flag.txt", jail_root)
        assert not allowed, "Bob should be blocked"
        # Should be blocked by first check (DAC)
        assert "DAC" in reason, f"Reason should mention DAC: {reason}"
    
    def test_eve_denied_access_to_flag(self):
        """Objective: Eve is denied by all three models."""
        jail_root = Path(__file__).parent.parent / "server" / "sftp_root"
        allowed, reason = authorize("eve", "read", "/secret_storage/flag.txt", jail_root)
        assert not allowed, "Eve should be denied access to flag"
    
    def test_alice_write_to_public_blocked_by_mac(self):
        """Objective: Alice blocked by MAC when trying to write to public (no write down)."""
        # First check that MAC blocks
        mac_allowed, mac_reason = _check_mac("alice", "write", "/public/test.txt")
        assert not mac_allowed, "MAC should block write down"


class TestAudit:
    """Test that audit records are written."""
    
    def test_audit_record_written(self):
        """Objective: Authorization decisions are logged to audit.jsonl."""
        jail_root = Path(__file__).parent.parent / "server" / "sftp_root"
        audit_file = Path(__file__).parent.parent / "server" / "audit.jsonl"
        
        # Record file size before
        initial_size = audit_file.stat().st_size if audit_file.exists() else 0
        
        # Make an authorization check
        authorize("alice", "read", "/test.txt", jail_root)
        
        # Check that audit file grew
        final_size = audit_file.stat().st_size
        assert final_size > initial_size, "Audit record should be written"
        
        # Read last line and verify fields
        with open(audit_file, 'r') as f:
            lines = f.readlines()
            last_line = lines[-1]
            import json
            record = json.loads(last_line)
            assert 'timestamp' in record
            assert record['user'] == 'alice'
            assert record['op'] == 'read'
            assert record['path'] == '/test.txt'
            assert 'allowed' in record
            assert 'reason' in record


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
