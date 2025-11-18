import json
import os
from pathlib import Path

from server.policy import authorize


AUDIT_PATH = Path(__file__).resolve().parent.parent / "server" / "audit.jsonl"


def _read_audit_lines():
    if not AUDIT_PATH.exists():
        return []
    with AUDIT_PATH.open("r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def test_audit_allow_and_deny(tmp_path):
    """Objective: authorize() writes an audit record for allow and deny decisions."""
    # Remove audit file if present to start clean
    try:
        if AUDIT_PATH.exists():
            AUDIT_PATH.unlink()
    except Exception:
        pass

    # 1) allow case: bob reading internal (should be allowed per mac_labels.json)
    allowed, reason = authorize("bob", "read", "/projects/internal/report.txt")
    assert allowed is True

    lines = _read_audit_lines()
    assert len(lines) >= 1
    last = lines[-1]
    assert last["user"] == "bob"
    assert last["op"] == "read"
    assert last["path"] == "/projects/internal/report.txt"
    assert last["allowed"] is True
    assert "reason" in last and isinstance(last["reason"], str)
    assert "timestamp" in last

    # 2) deny case: bob reading confidential (should be denied)
    allowed2, reason2 = authorize("bob", "read", "/projects/confidential/secret.txt")
    assert allowed2 is False

    lines2 = _read_audit_lines()
    assert len(lines2) >= 2
    last2 = lines2[-1]
    assert last2["user"] == "bob"
    assert last2["op"] == "read"
    assert last2["path"] == "/projects/confidential/secret.txt"
    assert last2["allowed"] is False
    assert "reason" in last2
    assert "timestamp" in last2
