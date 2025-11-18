import asyncio
import asyncssh
import argparse
import sys
import os
import getpass

class SFTPClient:
    def __init__(self, host, port, username, password):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.conn = None
        self.sftp = None

    async def connect(self):
        try:
            self.conn = await asyncssh.connect(
                self.host, port=self.port,
                username=self.username,
                password=self.password,
                known_hosts=None, # For testing, ignore known hosts or use TOFU
                client_keys=None
            )
            self.sftp = await self.conn.start_sftp_client()
            print(f"Connected to {self.host}:{self.port} as {self.username}")
        except Exception as e:
            print(f"Connection failed: {e}")
            sys.exit(1)

    async def run_shell(self):
        print("Type 'help' for commands. Type 'quit' to exit.")
        while True:
            try:
                cmd_line = await asyncio.get_event_loop().run_in_executor(None, input, "sftp> ")
                cmd_line = cmd_line.strip()
                if not cmd_line: continue
                
                parts = cmd_line.split()
                cmd = parts[0]
                args = parts[1:]
                
                if cmd == 'quit' or cmd == 'exit':
                    break
                elif cmd == 'help':
                    print("Commands: pwd, ls [path], mkdir <path>, stat <path>, get <rpath> [lpath], put <lpath> [rpath], quit")
                elif cmd == 'pwd':
                    print(await self.sftp.realpath('.'))
                elif cmd == 'ls':
                    path = args[0] if args else '.'
                    try:
                        files = await self.sftp.readdir(path)
                        for f in files:
                            # f is SFTPName, has filename, longname, attrs
                            print(f.longname if f.longname else f.filename)
                    except Exception as e:
                        print(f"Error: {e}")
                elif cmd == 'mkdir':
                    if not args: print("Usage: mkdir <path>"); continue
                    try:
                        await self.sftp.mkdir(args[0])
                        print(f"Created directory {args[0]}")
                    except Exception as e:
                        print(f"Error: {e}")
                elif cmd == 'stat':
                    if not args: print("Usage: stat <path>"); continue
                    try:
                        attrs = await self.sftp.stat(args[0])
                        print(attrs)
                    except Exception as e:
                        print(f"Error: {e}")
                elif cmd == 'get':
                    if not args: print("Usage: get <rpath> [lpath]"); continue
                    rpath = args[0]
                    lpath = args[1] if len(args) > 1 else os.path.basename(rpath)
                    try:
                        await self.sftp.get(rpath, lpath)
                        print(f"Downloaded {rpath} to {lpath}")
                    except Exception as e:
                        print(f"Error: {e}")
                elif cmd == 'put':
                    if not args: print("Usage: put <lpath> [rpath]"); continue
                    lpath = args[0]
                    rpath = args[1] if len(args) > 1 else os.path.basename(lpath)
                    try:
                        await self.sftp.put(lpath, rpath)
                        print(f"Uploaded {lpath} to {rpath}")
                    except Exception as e:
                        print(f"Error: {e}")
                else:
                    print("Unknown command")
            except EOFError:
                break
            except Exception as e:
                print(f"Error: {e}")

        if self.conn:
            self.conn.close()

async def main():
    parser = argparse.ArgumentParser(description="SFTP Client")
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=2222)
    parser.add_argument('--username', required=True)
    parser.add_argument('--password', help="Password (prompted if not provided)")
    
    args = parser.parse_args()
    
    password = args.password
    if not password:
        password = getpass.getpass(f"Password for {args.username}: ")
        
    client = SFTPClient(args.host, args.port, args.username, password)
    await client.connect()
    await client.run_shell()

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
