"""MAC policy implementation (Person 7 responsibilities for MAC).

This module implements Mandatory Access Control (MAC) enforcement with the
simple lattice: public < internal < confidential. It reads labels and user
clearances from `data/mac_labels.json` (must exist) with the format:

{
  "paths": { "/projects/confidential": "confidential", "/projects/internal": "internal" },
  "users": { "alice": "confidential", "bob": "internal", "eve": "public" }
}

The policy enforces:
- No read up: a user may read only if clearance >= resource label.
- No write down: a user may write only if clearance <= resource label.

`authorize(user, op, path)` returns (allowed: bool, reason: str) and always
appends an audit record to `server/audit.jsonl`.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Tuple


ROOT = Path(__file__).resolve().parent.parent
MAC_FILE = ROOT / "data" / "mac_labels.json"
AUDIT_PATH = Path(__file__).resolve().parent / "audit.jsonl"

# Label ordering
LABEL_ORDER: Dict[str, int] = {"public": 0, "internal": 1, "confidential": 2}


def _load_mac() -> Tuple[Dict[str, str], Dict[str, str]]:
	if not MAC_FILE.exists():
		raise FileNotFoundError(f"MAC labels file missing: {MAC_FILE}")
	with MAC_FILE.open("r", encoding="utf-8") as f:
		j = json.load(f)
	paths = j.get("paths", {})
	users = j.get("users", {})
	return paths, users


def _audit_record(user: str, op: str, path: str, allowed: bool, reason: str) -> None:
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


def _get_label_for_path(path: str, paths_map: Dict[str, str]) -> str:
	# Choose the longest matching prefix key from paths_map (POSIX-style)
	p_norm = Path(path).as_posix()
	best_label = "public"
	best_len = -1
	for prefix, label in paths_map.items():
		# normalize prefix
		pref = str(prefix)
		if not pref.startswith("/"):
			pref = "/" + pref
		if p_norm.startswith(pref) and len(pref) > best_len:
			best_len = len(pref)
			best_label = label
	return best_label


def authorize(user: str, op: str, path: str) -> Tuple[bool, str]:
	"""MAC authorize gate.

	Supported ops: 'read', 'list', 'stat', 'mkdir', 'write', 'realpath'
	For ops that are not read/write related we conservatively allow if MAC
	information doesn't block them.
	"""
	try:
		paths_map, users_map = _load_mac()
	except Exception as e:
		# Fail fast on malformed/missing MAC policy (per project requirements)
		reason = f"mac config error: {e}"
		_audit_record(user, op, path, False, reason)
		return False, reason

	user_label = users_map.get(user, "public")
	resource_label = _get_label_for_path(path, paths_map)

	user_rank = LABEL_ORDER.get(user_label, 0)
	res_rank = LABEL_ORDER.get(resource_label, 0)

	allowed = True
	reason = "ok"

	if op in ("read", "list", "stat", "realpath"):
		# No read up: user_rank >= res_rank
		if user_rank < res_rank:
			allowed = False
			reason = f"MAC: no read up (user={user_label} < resource={resource_label})"
	elif op in ("write", "mkdir"):
		# No write down: user_rank <= res_rank
		if user_rank > res_rank:
			allowed = False
			reason = f"MAC: no write down (user={user_label} > resource={resource_label})"
	else:
		# Unknown op: allow by default but audit
		allowed = True
		reason = "op-not-checked-by-MAC"

	_audit_record(user, op, path, allowed, reason)
	return allowed, reason

