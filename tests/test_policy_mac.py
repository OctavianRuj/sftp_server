import pytest

from server.policy import authorize


def test_mac_read_permissions():
    """User with internal clearance can read public and internal but not confidential."""
    # bob is internal per data/mac_labels.json
    allowed, reason = authorize("bob", "read", "/projects/internal/report.txt")
    assert allowed, f"expected bob to read internal: {reason}"

    allowed, reason = authorize("bob", "read", "/projects/public/info.txt")
    assert allowed, f"expected bob to read public: {reason}"

    allowed, reason = authorize("bob", "read", "/projects/confidential/secret.txt")
    assert not allowed, "expected bob to be denied reading confidential"


def test_mac_write_no_write_down():
    """Confidential user cannot write down into public; internal cannot write to public."""
    # alice is confidential
    allowed, reason = authorize("alice", "write", "/projects/confidential/data.bin")
    assert allowed, f"expected alice to write confidential: {reason}"

    allowed, reason = authorize("alice", "write", "/projects/internal/data.bin")
    assert not allowed, "expected alice to be denied writing down to internal"

    allowed, reason = authorize("alice", "write", "/projects/public/data.bin")
    assert not allowed, "expected alice to be denied writing down to public"

    # bob is internal: cannot write to public
    allowed, reason = authorize("bob", "write", "/projects/public/x")
    assert not allowed, "expected bob to be denied writing to public"

    # bob can write to confidential (write up allowed)
    allowed, reason = authorize("bob", "write", "/projects/confidential/x")
    assert allowed, f"expected bob to be allowed to write up: {reason}"