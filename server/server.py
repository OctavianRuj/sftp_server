import asyncio
import asyncssh
import os
import sys
import struct
import logging
import stat
import errno
from pathlib import Path
from auth import AuthManager
from policy import PolicyManager

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SFTPServer")

# Constants
SFTP_VERSION = 3
FXP_INIT = 1
FXP_VERSION = 2
FXP_OPEN = 3
FXP_CLOSE = 4
FXP_READ = 5
FXP_WRITE = 6
FXP_LSTAT = 7
FXP_FSTAT = 8
FXP_SETSTAT = 9
FXP_FSETSTAT = 10
FXP_OPENDIR = 11
FXP_READDIR = 12
FXP_REMOVE = 13
FXP_MKDIR = 14
FXP_RMDIR = 15
FXP_REALPATH = 16
FXP_STAT = 17
FXP_RENAME = 18
FXP_READLINK = 19
FXP_SYMLINK = 20
FXP_STATUS = 101
FXP_HANDLE = 102
FXP_DATA = 103
FXP_NAME = 104
FXP_ATTRS = 105
FXP_EXTENDED = 200
FXP_EXTENDED_REPLY = 201

# Status codes
FX_OK = 0
FX_EOF = 1
FX_NO_SUCH_FILE = 2
FX_PERMISSION_DENIED = 3
FX_FAILURE = 4
FX_BAD_MESSAGE = 5
FX_NO_CONNECTION = 6
FX_CONNECTION_LOST = 7
FX_OP_UNSUPPORTED = 8

class SFTPServer(asyncssh.SSHServer):
    def __init__(self, auth_manager):
        self.auth_manager = auth_manager

    def connection_made(self, conn):
        logger.info(f"Connection received from {conn.get_extra_info('peername')[0]}")

    def connection_lost(self, exc):
        if exc:
            logger.info(f"Connection lost: {exc}")
        else:
            logger.info("Connection closed")

    def begin_auth(self, username):
        return True # We require password auth

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        if self.auth_manager.verify_password(username, password):
            logger.info(f"User {username} authenticated successfully")
            return True
        logger.warning(f"Failed authentication for user {username}")
        return False

class SFTPHandler(asyncssh.SFTPServer):
    def __init__(self, conn, policy_manager, username):
        self.policy_manager = policy_manager
        self.username = username
        self.root = Path('server/sftp_root').resolve()
        if not self.root.exists():
            self.root.mkdir(parents=True)
        super().__init__(conn, chroot=self.root)
        logger.info(f"SFTP session started for user {username}, root: {self.root}")
    
    def _safe_path(self, path):
        """Convert virtual path to real path and ensure it's within root"""
        if isinstance(path, bytes):
            path = path.decode('utf-8')
        # Resolve and ensure within chroot
        full_path = (self.root / path.lstrip('/')).resolve()
        try:
            full_path.relative_to(self.root)
            return str(full_path)
        except ValueError:
            raise asyncssh.SFTPFailure(f"Access denied: path outside root")
    
    def _check_auth(self, operation, path):
        """Check if operation is authorized"""
        if isinstance(path, bytes):
            path = path.decode('utf-8')
        try:
            # Get virtual path relative to root
            real_path = self._safe_path(path)
            vpath = '/' + str(Path(real_path).relative_to(self.root))
        except:
            vpath = path if path else '/'
        allowed, reason = self.policy_manager.authorize(self.username, operation, vpath)
        if not allowed:
            logger.warning(f"Access denied for {self.username}: {operation} on {vpath} - {reason}")
            raise asyncssh.SFTPPermissionDenied(reason)
    
    async def realpath(self, path):
        """Canonicalize path"""
        try:
            real = self._safe_path(path)
            vpath = '/' + str(Path(real).relative_to(self.root))
            return vpath
        except Exception as e:
            logger.error(f"realpath error for {path}: {e}")
            return '/'
    
    async def stat(self, path):
        """Get file attributes"""
        self._check_auth('stat', path)
        real_path = self._safe_path(path)
        stat_result = os.stat(real_path)
        return asyncssh.SFTPAttrs.from_local(stat_result)
    
    async def lstat(self, path):
        """Get file attributes without following symlinks"""
        self._check_auth('stat', path)
        real_path = self._safe_path(path)
        stat_result = os.lstat(real_path)
        return asyncssh.SFTPAttrs.from_local(stat_result)
    
    async def open(self, path, pflags, attrs):
        """Open a file"""
        mode_map = {
            asyncssh.FXF_READ: 'read',
            asyncssh.FXF_WRITE: 'write',
        }
        op = 'write' if (pflags & asyncssh.FXF_WRITE) else 'read'
        self._check_auth(op, path)
        real_path = self._safe_path(path)
        return await super().open(real_path, pflags, attrs)
    
    async def close(self, file_obj):
        """Close a file"""
        return await super().close(file_obj)
    
    async def read(self, file_obj, offset, size):
        """Read from a file"""
        return await super().read(file_obj, offset, size)
    
    async def write(self, file_obj, offset, data):
        """Write to a file"""
        return await super().write(file_obj, offset, data)
    
    async def scandir(self, path):
        """List directory contents"""
        self._check_auth('opendir', path)
        real_path = self._safe_path(path)
        # Check if original path was bytes to match return type
        is_bytes = isinstance(path, bytes)
        for entry in os.scandir(real_path):
            vname = entry.name.encode('utf-8') if is_bytes else entry.name
            stat_result = entry.stat(follow_symlinks=False)
            attrs = asyncssh.SFTPAttrs.from_local(stat_result)
            yield asyncssh.SFTPName(vname, attrs=attrs)
    
    async def remove(self, path):
        """Remove a file"""
        self._check_auth('remove', path)
        real_path = self._safe_path(path)
        os.remove(real_path)
    
    async def mkdir(self, path, attrs):
        """Create a directory"""
        self._check_auth('mkdir', path)
        real_path = self._safe_path(path)
        os.mkdir(real_path)
    
    async def rmdir(self, path):
        """Remove a directory"""
        self._check_auth('rmdir', path)
        real_path = self._safe_path(path)
        os.rmdir(real_path)

async def start_server():
    auth_manager = AuthManager('data/users.json')
    policy_manager = PolicyManager('data', 'audit.jsonl')
    
    def sftp_factory(conn):
        username = conn.get_extra_info('username')
        return SFTPHandler(conn, policy_manager, username)

    await asyncssh.create_server(
        lambda: SFTPServer(auth_manager),
        '', 2222,
        server_host_keys=['server/ssh_host_ed25519_key'],
        sftp_factory=sftp_factory
    )
    
    logger.info("SFTP Server started on port 2222")

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(start_server())
        loop.run_forever()
    except (OSError, asyncssh.Error) as exc:
        sys.exit(f'Error starting server: {exc}')
    except KeyboardInterrupt:
        sys.exit('Server stopped by user')
