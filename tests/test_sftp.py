import asyncio
import os
from pathlib import Path
import struct
import tempfile

import pytest

from server import server as s
from server.policy import load_policy_data

@pytest.fixture(scope="module", autouse=True)
def setup_policy():
    load_policy_data()

# Helpers to build SFTP packets for the server handlers

def build_packet(msg_type: int, request_id: int, body: bytes = b"") -> bytes:
    return bytes([msg_type]) + struct.pack(">I", request_id) + body


def build_string(sval: str) -> bytes:
    b = sval.encode("utf-8")
    return struct.pack(">I", len(b)) + b


async def run_handler_and_get_payload(session: s.SFTPServerSession, coro):
    """Call an async handler and capture the single outgoing payload via monkeypatching session._send_packet."""
    out = []

    async def _capture(payload: bytes):
        out.append(payload)

    session._send_packet = _capture
    await coro
    assert out, "no packet was sent"
    return out[-1]


def unpack_string(data: bytes, offset: int = 0):
    length = struct.unpack_from(">I", data, offset)[0]
    offset += 4
    s = data[offset : offset + length].decode("utf-8")
    return s, offset + length


def parse_status(payload: bytes):
    # payload starts with type byte which we skip
    t = payload[0]
    assert t == s.SSH_FXP_STATUS
    rid = struct.unpack_from(">I", payload, 1)[0]
    code = struct.unpack_from(">I", payload, 5)[0]
    # message string at offset 9
    msg, _ = unpack_string(payload, 9)
    return rid, code, msg


def test_realpath_and_stat_and_read(tmp_path):
    async def _run():
        """Objective: REALPATH, STAT, OPEN (read-only), READ, CLOSE should work for a simple file."""
        # prepare jail root and file
        jail = tmp_path / "sftp_root"
        jail.mkdir()
        fpath = jail / "hello.txt"
        content = b"Hello SFTP world\n"
        fpath.write_bytes(content)

        session = s.SFTPServerSession(username="bob", jail_root=jail)

        # REALPATH
        pkt = build_packet(s.SSH_FXP_REALPATH, 1, build_string("/hello.txt"))
        payload = await run_handler_and_get_payload(session, session._handle_realpath(pkt))
        assert payload[0] == s.SSH_FXP_NAME

        # STAT
        pkt = build_packet(s.SSH_FXP_STAT, 2, build_string("/hello.txt"))
        payload = await run_handler_and_get_payload(session, session._handle_stat(pkt, lstat=False))
        assert payload[0] == s.SSH_FXP_ATTRS

        # OPEN (read)
        # build OPEN body: path string + pflags uint32
        body = build_string("/hello.txt") + struct.pack(">I", s.SSH_FXF_READ)
        pkt = build_packet(s.SSH_FXP_OPEN, 3, body)
        payload = await run_handler_and_get_payload(session, session._handle_open(pkt))
        assert payload[0] == s.SSH_FXP_HANDLE
        # extract handle string
        _rid = struct.unpack_from(">I", payload, 1)[0]
        handle_str, _ = unpack_string(payload, 5)

        # READ (offset 0, len 1024)
        read_body = build_string(handle_str)
        # append offset uint64 and len uint32
        read_body += struct.pack(">Q", 0)
        read_body += struct.pack(">I", 1024)
        pkt = bytes([s.SSH_FXP_READ]) + struct.pack(">I", 4) + read_body
        payload = await run_handler_and_get_payload(session, session._handle_read(pkt))
        assert payload[0] == s.SSH_FXP_DATA
        # parse data length
        rid = struct.unpack_from(">I", payload, 1)[0]
        data_len = struct.unpack_from(">I", payload, 5)[0]
        data = payload[9 : 9 + data_len]
        assert data == content

        # CLOSE
        close_body = build_string(handle_str)
        pkt = build_packet(s.SSH_FXP_CLOSE, 5, close_body)
        payload = await run_handler_and_get_payload(session, session._handle_close(pkt))
        rid, code, msg = parse_status(payload)
        assert code == s.SSH_FX_OK

    asyncio.run(_run())


def test_opendir_and_readdir(tmp_path):
    async def _run():
        """Objective: OPENDIR + READDIR returns directory entries and EOF."""
        jail = tmp_path / "sftp_root"
        jail.mkdir()
        d = jail / "somedir"
        d.mkdir()
        (d / "a.txt").write_text("a")
        (d / "b.txt").write_text("b")

        session = s.SFTPServerSession(username="bob", jail_root=jail)

        # OPENDIR
        pkt = build_packet(s.SSH_FXP_OPENDIR, 10, build_string("/somedir"))
        payload = await run_handler_and_get_payload(session, session._handle_opendir(pkt))
        assert payload[0] == s.SSH_FXP_HANDLE
        _rid = struct.unpack_from(">I", payload, 1)[0]
        handle_str, _ = unpack_string(payload, 5)

        # READDIR first batch
        read_body = build_string(handle_str)
        pkt = bytes([s.SSH_FXP_READDIR]) + struct.pack(">I", 11) + read_body
        payload = await run_handler_and_get_payload(session, session._handle_readdir(pkt))
        assert payload[0] == s.SSH_FXP_NAME
        # parse count
        count = struct.unpack_from(">I", payload, 5)[0]
        assert count >= 2

        # READDIR again should eventually return EOF when exhausted
        payload = await run_handler_and_get_payload(session, session._handle_readdir(pkt))
        assert payload[0] == s.SSH_FXP_STATUS
        rid, code, msg = parse_status(payload)
        assert code == s.SSH_FX_EOF

    asyncio.run(_run())

