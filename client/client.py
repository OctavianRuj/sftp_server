import asyncio
import asyncssh
import sys
import os
from pathlib import Path

class SFTPClient:    
    def __init__(self, host='localhost', port=8022, username='', password=''):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.conn = None
        self.sftp = None
    
    async def connect(self):
        try:
            self.conn = await asyncssh.connect(
                self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                known_hosts=None,
                server_host_key_algs=['ssh-ed25519', 'ssh-rsa', 'rsa-sha2-256', 'rsa-sha2-512']
            )
            self.sftp = await self.conn.start_sftp_client()
            print(f"Connected to {self.host}:{self.port} as {self.username}")
            return True
        except asyncssh.HostKeyNotVerifiable as e:
            print(f"Host key verification failed: {e}")
            print("You may need to add the host key to your known_hosts file.")
            return False
        except asyncssh.PermissionDenied:
            print("Authentication failed: Permission denied")
            return False
        except Exception as e:
            print(f"Connection failed: {e}")
            return False
    
    async def disconnect(self):
        if self.sftp:
            self.sftp.exit()
        if self.conn:
            self.conn.close()
            await self.conn.wait_closed()
    
    async def cmd_pwd(self):
        try:
            cwd = await self.sftp.getcwd()
            if cwd is None:
                cwd = '/'
            print(cwd)
        except Exception as e:
            print(f"Error: {e}")
    
    async def cmd_ls(self, path='.'):
        try:
            entries = await self.sftp.readdir(path)
            for entry in entries:
                print(entry.filename)
        except asyncssh.SFTPNoSuchFile:
            print(f"Error: No such file or directory: {path}")
        except asyncssh.SFTPPermissionDenied:
            print(f"Error: Permission denied: {path}")
        except Exception as e:
            print(f"Error: {e}")
    
    async def cmd_mkdir(self, path):
        try:
            await self.sftp.mkdir(path)
            print(f"Directory created: {path}")
        except asyncssh.SFTPFailure:
            print(f"Error: Failed to create directory: {path}")
        except asyncssh.SFTPPermissionDenied:
            print(f"Error: Permission denied: {path}")
        except Exception as e:
            print(f"Error: {e}")
    
    async def cmd_stat(self, path):
        try:
            attrs = await self.sftp.stat(path)
            print(f"Size: {attrs.size}")
            print(f"Permissions: {oct(attrs.permissions)}")
            print(f"UID: {attrs.uid}")
            print(f"GID: {attrs.gid}")
            print(f"Modified: {attrs.mtime}")
        except asyncssh.SFTPNoSuchFile:
            print(f"Error: No such file or directory: {path}")
        except Exception as e:
            print(f"Error: {e}")
    
    async def cmd_get(self, remote_path, local_path=None):
        try:
            if local_path is None:
                local_path = os.path.basename(remote_path)
            
            await self.sftp.get(remote_path, local_path)
            print(f"Downloaded: {remote_path} -> {local_path}")
        except asyncssh.SFTPNoSuchFile:
            print(f"Error: No such file: {remote_path}")
        except asyncssh.SFTPPermissionDenied:
            print(f"Error: Permission denied: {remote_path}")
        except Exception as e:
            print(f"Error: {e}")
    
    async def cmd_put(self, local_path, remote_path=None):
        try:
            if remote_path is None:
                remote_path = os.path.basename(local_path)
            
            if not os.path.exists(local_path):
                print(f"Error: Local file not found: {local_path}")
                return
            
            await self.sftp.put(local_path, remote_path)
            print(f"Uploaded: {local_path} -> {remote_path}")
        except asyncssh.SFTPPermissionDenied:
            print(f"Error: Permission denied: {remote_path}")
        except Exception as e:
            print(f"Error: {e}")
    
    async def run_cli(self):
        print("SFTP CLI - Type 'help' for commands, 'quit' to exit")
        
        while True:
            try:
                command = input("sftp> ").strip()
                
                if not command:
                    continue
                
                parts = command.split()
                cmd = parts[0].lower()
                
                if cmd == 'quit' or cmd == 'exit':
                    break
                elif cmd == 'help':
                    self.print_help()
                elif cmd == 'pwd':
                    await self.cmd_pwd()
                elif cmd == 'ls':
                    path = parts[1] if len(parts) > 1 else '.'
                    await self.cmd_ls(path)
                elif cmd == 'mkdir':
                    if len(parts) < 2:
                        print("Usage: mkdir <path>")
                    else:
                        await self.cmd_mkdir(parts[1])
                elif cmd == 'stat':
                    if len(parts) < 2:
                        print("Usage: stat <path>")
                    else:
                        await self.cmd_stat(parts[1])
                elif cmd == 'get':
                    if len(parts) < 2:
                        print("Usage: get <remote_path> [local_path]")
                    else:
                        local = parts[2] if len(parts) > 2 else None
                        await self.cmd_get(parts[1], local)
                elif cmd == 'put':
                    if len(parts) < 2:
                        print("Usage: put <local_path> [remote_path]")
                    else:
                        remote = parts[2] if len(parts) > 2 else None
                        await self.cmd_put(parts[1], remote)
                else:
                    print(f"Unknown command: {cmd}. Type 'help' for available commands.")
            
            except KeyboardInterrupt:
                print("\nUse 'quit' to exit")
            except EOFError:
                break
            except Exception as e:
                print(f"Error: {e}")
    
    def print_help(self):
        print("\nAvailable commands:")
        print("  pwd                      - Print current working directory")
        print("  ls [path]               - List directory contents")
        print("  mkdir <path>            - Create a directory")
        print("  stat <path>             - Print file/directory attributes")
        print("  get <rpath> [lpath]     - Download file")
        print("  put <lpath> [rpath]     - Upload file")
        print("  quit                    - Exit the client")
        print()


async def main():
    if len(sys.argv) < 4:
        print("Usage: python client.py <host> <username> <password> [port]")
        print("Example: python client.py localhost alice password123 8022")
        sys.exit(1)
    
    host = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    port = int(sys.argv[4]) if len(sys.argv) > 4 else 8022
    
    client = SFTPClient(host, port, username, password)
    
    if await client.connect():
        try:
            await client.run_cli()
        finally:
            await client.disconnect()
            print("Disconnected.")


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nExiting...")
