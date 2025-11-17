"""
server/server.py

Person 4 focus:
- SFTP v3 server-side logic for read/stat-ish operations:
  REALPATH, STAT, LSTAT, FSTAT, OPENDIR, READDIR, OPEN (read-only), CLOSE

Other stuff (WRITE, MKDIR, etc.) can be added later by the rest of the group.
"""

import asyncio
import os
import struct
import uuid
from pathlib import Path

import asyncssh

# Use a package-relative import so the module works when imported as `server.server`
from .policy import authorize  # unified DAC+MAC+RBAC gate: authorize(user, op, path)


# === SFTP v3 constants (only the ones we actually need) ===

# Message types (subset)
SSH_FXP_INIT = 1
SSH_FXP_VERSION = 2
SSH_FXP_OPEN = 3
SSH_FXP_CLOSE = 4
SSH_FXP_READ = 5
SSH_FXP_WRITE = 6
SSH_FXP_LSTAT = 7
SSH_FXP_FSTAT = 8
SSH_FXP_SETSTAT = 9
SSH_FXP_FSETSTAT = 10
SSH_FXP_OPENDIR = 11
SSH_FXP_READDIR = 12
SSH_FXP_STAT = 17
SSH_FXP_REALPATH = 16
SSH_FXP_STATUS = 101
SSH_FXP_HANDLE = 102
SSH_FXP_DATA = 103
SSH_FXP_NAME = 104
SSH_FXP_ATTRS = 105

# Status codes (from spec)
SSH_FX_OK = 0
SSH_FX_EOF = 1
SSH_FX_NO_SUCH_FILE = 2
SSH_FX_PERMISSION_DENIED = 3
SSH_FX_FAILURE = 4

# OPEN pflags (bitmask)
SSH_FXF_READ = 0x00000001
SSH_FXF_WRITE = 0x00000002
SSH_FXF_APPEND = 0x00000004
SSH_FXF_CREAT = 0x00000008
SSH_FXF_TRUNC = 0x00000010
SSH_FXF_EXCL = 0x00000020

# ATTRS flags – we only really care about size, perms and times here
SSH_FILEXFER_ATTR_SIZE = 0x00000001
SSH_FILEXFER_ATTR_UIDGID = 0x00000002
SSH_FILEXFER_ATTR_PERMISSIONS = 0x00000004
SSH_FILEXFER_ATTR_ACMODTIME = 0x00000008


# --- Helper pack/unpack functions (just doing basic SFTP framing) ---

def pack_uint32(value: int) -> bytes:
    # big-endian 4-byte int
    return struct.pack(">I", value)


def unpack_uint32(data: bytes, offset: int = 0):
    # returns (value, new_offset)
    return struct.unpack_from(">I", data, offset)[0], offset + 4


def pack_string(s: str) -> bytes:
    # SFTP strings are length-prefixed utf-8
    encoded = s.encode("utf-8")
    return pack_uint32(len(encoded)) + encoded


def unpack_string(data: bytes, offset: int = 0):
    # read length-prefixed string; again returns (string, new_offset)
    length, offset = unpack_uint32(data, offset)
    s = data[offset : offset + length].decode("utf-8")
    return s, offset + length


def pack_attrs_from_stat(st: os.stat_result) -> bytes:
    """
    Build an SFTP ATTRS structure from os.stat().

    This is not super fancy, but good enough:
    - flags: size, permissions, acmodtime
    - size: st.st_size
    - permissions: st.st_mode (includes file type bits)
    - atime, mtime: ints
    """
    flags = SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_PERMISSIONS | SSH_FILEXFER_ATTR_ACMODTIME
    attrs = pack_uint32(flags)
    # size is uint64 in SFTP
    attrs += struct.pack(">Q", st.st_size)
    # we skip uid/gid for now (would need SSH_FILEXFER_ATTR_UIDGID)
    attrs += pack_uint32(st.st_mode)
    attrs += pack_uint32(int(st.st_atime))
    attrs += pack_uint32(int(st.st_mtime))
    return attrs


def safe_join(jail_root: Path, sftp_path: str) -> Path:
    """
    Canonicalize a POSIX SFTP path and join it safely under jail_root.

    - Paths from the client are POSIX style and *rooted at the jail*.
    - We normalize ".", "..", duplicate slashes etc.
    - If the final resolved path escapes the jail_root, we blow up with ValueError.

    This is basically the "no directory traversal" defense.
    """
    # empty or "." → just the root
    if not sftp_path or sftp_path == ".":
        sftp_path = "/"

    # treat all incoming paths as absolute from the jail root
    if sftp_path.startswith("/"):
        sftp_path = sftp_path.lstrip("/")

    # compute candidate inside the jail
    candidate = (jail_root / sftp_path).resolve()

    try:
        jail_root_resolved = jail_root.resolve()
    except FileNotFoundError:
        # in case the jail doesn't exist yet, just create it once
        jail_root.mkdir(parents=True, exist_ok=True)
        jail_root_resolved = jail_root.resolve()

    # Make sure candidate is *under* jail_root, otherwise it's traversal
    try:
        candidate.relative_to(jail_root_resolved)
    except ValueError:
        # not inside jail_root, so reject
        raise ValueError(f"path escapes jail: {sftp_path!r}")

    return candidate


class HandleEntry:
    """
    Simple little holder for file/dir handles.
    """
    def __init__(self, handle_id: bytes, path: Path, kind: str, obj):
        self.handle_id = handle_id  # bytes we send to the client as "handle"
        self.path = path            # full canonical Path
        self.kind = kind            # either "file" or "dir"
        self.obj = obj              # actual file object or dir state


class HandleTable:
    """
    Trivial in-memory table of open handles.

    This is used for:
    - FSTAT (needs a valid file handle)
    - READDIR (directory handle)
    - CLOSE (closing either)
    """
    def __init__(self):
        self._by_id: dict[bytes, HandleEntry] = {}

    def create_file_handle(self, path: Path, file_obj) -> bytes:
        # random-ish handle id via uuid (good enough)
        handle_id = uuid.uuid4().bytes
        entry = HandleEntry(handle_id, path, "file", file_obj)
        self._by_id[handle_id] = entry
        return handle_id

    def create_dir_handle(self, path: Path, dir_iter_state) -> bytes:
        handle_id = uuid.uuid4().bytes
        entry = HandleEntry(handle_id, path, "dir", dir_iter_state)
        self._by_id[handle_id] = entry
        return handle_id

    def get(self, handle_id: bytes) -> HandleEntry | None:
        # just a wrapper, nothing fancy
        return self._by_id.get(handle_id)

    def pop(self, handle_id: bytes) -> HandleEntry | None:
        # remove and return; used by CLOSE
        return self._by_id.pop(handle_id, None)


class SFTPServerSession(asyncssh.SSHServerSession):
    """
    One SSH "session" where the client runs the SFTP subsystem.

    We basically:
    - read length-prefixed SFTP packets from the channel
    - dispatch based on type
    - write back SFTP packets
    """

    def __init__(self, username: str, jail_root: Path):
        self._chan = None
        self._username = username
        self._jail_root = jail_root
        self._handles = HandleTable()
        self._loop_task = None

    def connection_made(self, chan):
        # store channel so we can read/write later
        self._chan = chan

    def session_started(self):
        # kick off the SFTP loop (async)
        self._loop_task = asyncio.create_task(self._sftp_loop())

    async def _sftp_loop(self):
        """
        Main SFTP receive loop.

        Reads packets, checks the type, and calls the right handler.
        Also does the INIT→VERSION exchange.
        """
        try:
            while True:
                pkt = await self._read_packet()
                if pkt is None:
                    # channel closed or EOF
                    break

                msg_type = pkt[0]

                if msg_type == SSH_FXP_INIT:
                    await self._handle_init(pkt)
                    # then we keep processing stuff
                elif msg_type == SSH_FXP_REALPATH:
                    await self._handle_realpath(pkt)
                elif msg_type == SSH_FXP_STAT:
                    await self._handle_stat(pkt, lstat=False)
                elif msg_type == SSH_FXP_LSTAT:
                    await self._handle_stat(pkt, lstat=True)
                elif msg_type == SSH_FXP_FSTAT:
                    await self._handle_fstat(pkt)
                elif msg_type == SSH_FXP_OPENDIR:
                    await self._handle_opendir(pkt)
                elif msg_type == SSH_FXP_READDIR:
                    await self._handle_readdir(pkt)
                elif msg_type == SSH_FXP_OPEN:
                    await self._handle_open(pkt)
                elif msg_type == SSH_FXP_READ:
                    await self._handle_read(pkt)
                elif msg_type == SSH_FXP_CLOSE:
                    await self._handle_close(pkt)
                else:
                    # anything we don't implement → generic FAILURE
                    await self._reply_status_unknown(pkt)
        except (asyncio.CancelledError, OSError):
            # not going to be fancy with errors here
            pass
        finally:
            # cleanup: close any still-open file handles
            for entry in list(self._handles._by_id.values()):
                if entry.kind == "file":
                    try:
                        entry.obj.close()
                    except Exception:
                        # if close fails, not much we can do
                        pass
            self._handles._by_id.clear()

    async def _read_packet(self) -> bytes | None:
        """
        Read one SFTP packet from the channel.

        Format:
        - 4 bytes length (big endian)
        - [length] bytes payload
        """
        header = await self._chan.readexactly(4)
        if not header:
            return None
        (length,) = struct.unpack(">I", header)
        payload = await self._chan.readexactly(length)
        if not payload:
            return None
        return payload

    async def _send_packet(self, payload: bytes):
        """
        Send a SFTP packet (prefix with length).
        """
        length = pack_uint32(len(payload))
        self._chan.write(length + payload)

    # === Individual SFTP message handlers ===

    async def _handle_init(self, pkt: bytes):
        """
        SSH_FXP_INIT:
        client says "I speak SFTP version X", we answer with VERSION(3).
        """
        # We don't actually care about client version; we just say 3.
        payload = bytes([SSH_FXP_VERSION]) + pack_uint32(3)
        # could add extensions here if we wanted to (we don't)
        await self._send_packet(payload)

    async def _handle_realpath(self, pkt: bytes):
        """
        REALPATH:
        - resolve a path inside the jail
        - return canonical POSIX path via SSH_FXP_NAME
        """
        # pkt: [type:1][id:uint32][path:string]
        # a bit redundant here but it's clear enough
        _, offset = unpack_uint32(pkt, 1)  # skip id to get offset
        request_id = struct.unpack_from(">I", pkt, 1)[0]
        path, _ = unpack_string(pkt, offset)

        try:
            full_path = safe_join(self._jail_root, path)
        except ValueError:
            # path tried to escape the jail
            await self._send_status(request_id, SSH_FX_PERMISSION_DENIED, "path escapes jail")
            return

        # call the unified gate so DAC/MAC/RBAC all get a say
        allowed, reason = authorize(self._username, "realpath", str(full_path))
        if not allowed:
            await self._send_status(request_id, SSH_FX_PERMISSION_DENIED, reason)
            return

        # produce a "nice" path relative to jail, but prefixed with "/"
        jail_root = self._jail_root.resolve()
        rel = full_path.resolve().relative_to(jail_root)
        if str(rel) == ".":
            canonical_sftp_path = "/"
        else:
            canonical_sftp_path = "/" + str(rel).replace("\\", "/")

        # NAME packet: [type][id][count][name][longname][attrs]
        payload = bytes([SSH_FXP_NAME])
        payload += pack_uint32(request_id)
        payload += pack_uint32(1)  # one entry
        payload += pack_string(canonical_sftp_path)
        payload += pack_string(canonical_sftp_path)  # we reuse as longname

        # try to stat so we can return attrs; if it fails, send empty attrs
        try:
            st = full_path.stat()
            attrs = pack_attrs_from_stat(st)
        except FileNotFoundError:
            attrs = pack_uint32(0)  # 0 flags → no attrs

        payload += attrs
        await self._send_packet(payload)

    async def _handle_stat(self, pkt: bytes, lstat: bool):
        """
        STAT / LSTAT:
        - STAT follows symlinks
        - LSTAT doesn't
        """
        # msg_type not really used, but leaving it for clarity
        _msg_type = SSH_FXP_STAT if not lstat else SSH_FXP_LSTAT

        # pkt: [type][id][path]
        _, offset = unpack_uint32(pkt, 1)
        request_id = struct.unpack_from(">I", pkt, 1)[0]
        path, _ = unpack_string(pkt, offset)

        try:
            full_path = safe_join(self._jail_root, path)
        except ValueError:
            await self._send_status(request_id, SSH_FX_PERMISSION_DENIED, "path escapes jail")
            return

        # generic "stat" op for auth
        allowed, reason = authorize(self._username, "stat", str(full_path))
        if not allowed:
            await self._send_status(request_id, SSH_FX_PERMISSION_DENIED, reason)
            return

        try:
            if lstat:
                st = os.lstat(full_path)
            else:
                st = os.stat(full_path)
        except FileNotFoundError:
            await self._send_status(request_id, SSH_FX_NO_SUCH_FILE, "no such file")
            return
        except PermissionError:
            await self._send_status(request_id, SSH_FX_PERMISSION_DENIED, "permission denied")
            return
        except OSError as e:
            # generic failure for whatever else (IO errors etc.)
            await self._send_status(request_id, SSH_FX_FAILURE, str(e))
            return

        attrs = pack_attrs_from_stat(st)
        payload = bytes([SSH_FXP_ATTRS]) + pack_uint32(request_id) + attrs
        await self._send_packet(payload)

    async def _handle_fstat(self, pkt: bytes):
        """
        FSTAT:
        Stat an already opened file handle (so no path here, just handle).
        """
        request_id = struct.unpack_from(">I", pkt, 1)[0]
        offset = 5
        handle, _ = unpack_string(pkt, offset)
        # we encoded handle bytes via latin-1 earlier, so reverse that
        handle_id = handle.encode("latin-1", errors="ignore")

        entry = self._handles.get(handle_id)
        if not entry or entry.kind != "file":
            await self._send_status(request_id, SSH_FX_FAILURE, "invalid file handle")
            return

        full_path = entry.path
        allowed, reason = authorize(self._username, "stat", str(full_path))
        if not allowed:
            await self._send_status(request_id, SSH_FX_PERMISSION_DENIED, reason)
            return

        try:
            st = os.fstat(entry.obj.fileno())
        except OSError as e:
            await self._send_status(request_id, SSH_FX_FAILURE, str(e))
            return

        attrs = pack_attrs_from_stat(st)
        payload = bytes([SSH_FXP_ATTRS]) + pack_uint32(request_id) + attrs
        await self._send_packet(payload)

    async def _handle_opendir(self, pkt: bytes):
        """
        OPENDIR:
        Open a directory handle so client can call READDIR.
        """
        request_id = struct.unpack_from(">I", pkt, 1)[0]
        _, offset = unpack_uint32(pkt, 1)
        path, _ = unpack_string(pkt, offset)

        try:
            full_path = safe_join(self._jail_root, path)
        except ValueError:
            await self._send_status(request_id, SSH_FX_PERMISSION_DENIED, "path escapes jail")
            return

        allowed, reason = authorize(self._username, "list", str(full_path))
        if not allowed:
            await self._send_status(request_id, SSH_FX_PERMISSION_DENIED, reason)
            return

        if not full_path.exists() or not full_path.is_dir():
            await self._send_status(request_id, SSH_FX_NO_SUCH_FILE, "not a directory")
            return

        # we just pre-scan the entries into a list; not super efficient for huge dirs
        entries = list(os.scandir(full_path))
        dir_state = {"entries": entries, "index": 0}
        handle_id = self._handles.create_dir_handle(full_path, dir_state)

        payload = bytes([SSH_FXP_HANDLE]) + pack_uint32(request_id)
        # send handle id as a string (we decode the raw bytes using latin-1)
        payload += pack_string(handle_id.decode("latin-1", errors="ignore"))
        await self._send_packet(payload)

    async def _handle_readdir(self, pkt: bytes):
        """
        READDIR:
        Return zero or more directory entries for an open directory handle.
        When done, we reply with STATUS(EOF).
        """
        request_id = struct.unpack_from(">I", pkt, 1)[0]
        offset = 5
        handle, _ = unpack_string(pkt, offset)
        handle_id = handle.encode("latin-1", errors="ignore")

        entry = self._handles.get(handle_id)
        if not entry or entry.kind != "dir":
            await self._send_status(request_id, SSH_FX_FAILURE, "invalid directory handle")
            return

        dir_state = entry.obj
        entries = dir_state["entries"]
        index = dir_state["index"]

        if index >= len(entries):
            # nothing left → EOF
            await self._send_status(request_id, SSH_FX_EOF, "end of directory")
            return

        # send at most 50 entries at a time (arbitrary chunk size)
        batch = entries[index : index + 50]
        dir_state["index"] = index + len(batch)

        payload = bytes([SSH_FXP_NAME]) + pack_uint32(request_id)
        payload += pack_uint32(len(batch))
        for e in batch:
            name = e.name
            longname = name  # could add full ls-style "ls -l" string but meh
            payload += pack_string(name)
            payload += pack_string(longname)
            try:
                st = e.stat(follow_symlinks=False)
                attrs = pack_attrs_from_stat(st)
            except FileNotFoundError:
                # file disappeared between scandir and here, just send empty attrs
                attrs = pack_uint32(0)
            payload += attrs

        await self._send_packet(payload)

    async def _handle_open(self, pkt: bytes):
        """
        OPEN (read-only variant):

        We only allow SSH_FXF_READ. Any write-ish pflags will be rejected.
        """
        request_id = struct.unpack_from(">I", pkt, 1)[0]
        offset = 5
        path, offset = unpack_string(pkt, offset)
        pflags, offset = unpack_uint32(pkt, offset)

        # Only allow pure read. If any write/append/creat flags are set -> nope.
        allowed_flags = SSH_FXF_READ
        if pflags & ~allowed_flags:
            await self._send_status(request_id, SSH_FX_PERMISSION_DENIED, "write not allowed")
            return

        try:
            full_path = safe_join(self._jail_root, path)
        except ValueError:
            await self._send_status(request_id, SSH_FX_PERMISSION_DENIED, "path escapes jail")
            return

        allowed, reason = authorize(self._username, "read", str(full_path))
        if not allowed:
            await self._send_status(request_id, SSH_FX_PERMISSION_DENIED, reason)
            return

        if not full_path.exists() or not full_path.is_file():
            await self._send_status(request_id, SSH_FX_NO_SUCH_FILE, "no such file")
            return

        try:
            f = open(full_path, "rb")
        except PermissionError:
            await self._send_status(request_id, SSH_FX_PERMISSION_DENIED, "permission denied")
            return
        except OSError as e:
            await self._send_status(request_id, SSH_FX_FAILURE, str(e))
            return

        handle_id = self._handles.create_file_handle(full_path, f)
        payload = bytes([SSH_FXP_HANDLE]) + pack_uint32(request_id)
        payload += pack_string(handle_id.decode("latin-1", errors="ignore"))
        await self._send_packet(payload)

    async def _handle_read(self, pkt: bytes):
        """
        READ:

        Packet format (payload after msg type):
        [id:uint32][handle:string][offset:uint64][len:uint32]

        Reply with DATA (one or more) or STATUS(EOF).
        """
        request_id = struct.unpack_from(">I", pkt, 1)[0]
        offset = 5
        handle, offset = unpack_string(pkt, offset)
        # offset is uint64
        read_offset = struct.unpack_from(">Q", pkt, offset)[0]
        offset += 8
        read_len, _ = unpack_uint32(pkt, offset)

        handle_id = handle.encode("latin-1", errors="ignore")
        entry = self._handles.get(handle_id)
        if not entry or entry.kind != "file":
            await self._send_status(request_id, SSH_FX_FAILURE, "invalid file handle")
            return

        full_path = entry.path
        allowed, reason = authorize(self._username, "read", str(full_path))
        if not allowed:
            await self._send_status(request_id, SSH_FX_PERMISSION_DENIED, reason)
            return

        try:
            fobj = entry.obj
            fobj.seek(read_offset)
            data = fobj.read(read_len)
        except OSError as e:
            await self._send_status(request_id, SSH_FX_FAILURE, str(e))
            return

        if not data:
            # EOF
            await self._send_status(request_id, SSH_FX_EOF, "EOF")
            return

        payload = bytes([SSH_FXP_DATA]) + pack_uint32(request_id)
        payload += pack_uint32(len(data))
        payload += data
        await self._send_packet(payload)

    async def _handle_close(self, pkt: bytes):
        """
        CLOSE:
        Closes a file or directory handle (both use same message).
        """
        request_id = struct.unpack_from(">I", pkt, 1)[0]
        offset = 5
        handle, _ = unpack_string(pkt, offset)
        handle_id = handle.encode("latin-1", errors="ignore")

        entry = self._handles.pop(handle_id)
        if not entry:
            await self._send_status(request_id, SSH_FX_FAILURE, "invalid handle")
            return

        if entry.kind == "file":
            try:
                entry.obj.close()
            except Exception:
                # if closing fails, we still pretend it closed; better than leaking handles forever
                pass

        await self._send_status(request_id, SSH_FX_OK, "closed")

    async def _reply_status_unknown(self, pkt: bytes):
        """
        Fallback for any message types we don't handle explicitly.
        """
        request_id = struct.unpack_from(">I", pkt, 1)[0] if len(pkt) >= 5 else 0
        await self._send_status(request_id, SSH_FX_FAILURE, "unsupported operation")

    async def _send_status(self, request_id: int, code: int, message: str = ""):
        """
        Send a STATUS packet.

        Format:
        [type][id][code:uint32][message:string][language:string]
        """
        payload = bytes([SSH_FXP_STATUS])
        payload += pack_uint32(request_id)
        payload += pack_uint32(code)
        payload += pack_string(message)
        # language tag is optional; just leave empty
        payload += pack_string("")
        await self._send_packet(payload)


class SFTPSSHServer(asyncssh.SSHServer):
    """
    SSH server wrapper that spawns our SFTPServerSession for the 'sftp' subsystem.

    Auth itself (password checking etc.) should be done in auth.py or via asyncssh
    hooks; Person 4 just wires it up.
    """

    def __init__(self, jail_root: Path):
        super().__init__()
        self._jail_root = jail_root

    def begin_auth(self, username):
        # we return True to say "yes, we want to do auth" (asyncssh handles details)
        return True

    def session_requested(self):
        # we need the username from the connection object
        username = self._conn.get_extra_info("username")
        return SFTPServerSession(username=username, jail_root=self._jail_root)


async def start_server(host: str = "127.0.0.1", port: int = 2222):
    """
    Entry point to run the SSH+SFTP server.

    Before running this, you need to create a host key, e.g.:

        ssh-keygen -t ed25519 -N '' -f server/ssh_host_ed25519_key
    """
    jail_root = Path(__file__).resolve().parent / "sftp_root"
    # just make sure jail root exists
    jail_root.mkdir(parents=True, exist_ok=True)

    server = await asyncssh.create_server(
        lambda: SFTPSSHServer(jail_root=jail_root),
        host,
        port,
        server_host_keys=["server/ssh_host_ed25519_key"],
        # actual password auth policy belongs somewhere else (auth.py / asyncssh config)
    )

    print(f"SFTP server listening on {host}:{port}, jail root = {jail_root}")
    return server


def main():
    loop = asyncio.get_event_loop()
    try:
        server = loop.run_until_complete(start_server())
        loop.run_forever()
    except (OSError, asyncssh.Error) as exc:
        print("Error starting server:", exc)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
