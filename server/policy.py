"""
Minimal policy gate for Person 4 (read/stat handlers).

This file provides a small, well-documented placeholder implementation of
`authorize(user, op, path)` that currently follows a permissive policy so the
SFTP read/stat handlers can be exercised and tested. The full DAC/MAC/RBAC
implementation belongs to Persons 6/7 and will replace this later.

Behavior:
 - authorize(...) -> (allowed: bool, reason: str)
 - default: allow all read/list/stat operations; deny unknown ops

It also writes a simple audit line to `server/audit.jsonl` for each decision.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Tuple


AUDIT_PATH = Path(__file__).resolve().parent / "audit.jsonl"


def _audit_record(user: str, op: str, path: str, allowed: bool, reason: str) -> None:
	rec = {
		"timestamp": datetime.utcnow().isoformat() + "Z",
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
		# audit failures should not block operations in this minimal stub
		pass


def authorize(user: str, op: str, path: str) -> Tuple[bool, str]:
	"""Minimal authorize gate.

	For Person 4 work (read/stat handlers) we allow the required read/list/stat
	operations. Unknown operations return (False, reason).
	"""
	read_ops = {"realpath", "stat", "lstat", "fstat", "list", "read"}
	if op in read_ops:
		reason = "permissive-allow-stub"
		_audit_record(user, op, path, True, reason)
		return True, reason

	reason = "operation-not-implemented-in-stub"
	_audit_record(user, op, path, False, reason)
	return False, reason
