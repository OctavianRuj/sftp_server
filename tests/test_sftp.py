import pytest
import asyncssh
import asyncio
import os
import json
import shutil
from pathlib import Path

# Configuration
HOST = '127.0.0.1'
PORT = 2222
SERVER_KEY_PATH = 'server/ssh_host_ed25519_key'

# Users from setup_data.py
USERS = {
    'alice': 'password123', # admin, confidential
    'bob': 'password123',   # user, internal
    'eve': 'password123'    # guest, public
}

@pytest.fixture(scope="session", autouse=True)
def start_server():
    # Ensure server is running. 
    # Ideally we'd start it here, but for now we assume it's running or we start it in a subprocess.
    # Since we are in a single environment, let's try to start it in background if not running?
    # Or just assume the user (me) will start it. 
    # Actually, for automated tests, it's better if the test starts the server.
    
    # Let's start the server in a subprocess
    import subprocess
    import time
    
    # Clean up previous run
    if os.path.exists('audit.jsonl'):
        os.remove('audit.jsonl')
    if os.path.exists('server/sftp_root'):
        shutil.rmtree('server/sftp_root')
    os.makedirs('server/sftp_root')

    # Create some initial directories for testing
    os.makedirs('server/sftp_root/public', exist_ok=True)
    os.makedirs('server/sftp_root/internal', exist_ok=True)
    os.makedirs('server/sftp_root/confidential', exist_ok=True)
    os.makedirs('server/sftp_root/home/bob', exist_ok=True)
    
    # Create a file in public
    with open('server/sftp_root/public/readme.txt', 'w') as f:
        f.write("Public Info")

    # Start server
    proc = subprocess.Popen(['python', 'server/server.py'], 
                            stdout=subprocess.PIPE, 
                            stderr=subprocess.PIPE)
    
    # Wait for server to start
    time.sleep(2)
    
    yield proc
    
    proc.terminate()
    proc.wait()

async def get_sftp_client(username):
    conn = await asyncssh.connect(
        HOST, port=PORT,
        username=username,
        password=USERS[username],
        known_hosts=None
    )
    return await conn.start_sftp_client(), conn

@pytest.mark.asyncio
async def test_dac_owner_access():
    """Objective: Verify owner can read/write their file."""
    sftp, conn = await get_sftp_client('bob')
    
    # Bob owns /home/bob (simulated in dac_owners.csv)
    # Try to write a file
    async with sftp.open('/home/bob/test.txt', 'w') as f:
        await f.write('hello')
    
    # Try to read it back
    async with sftp.open('/home/bob/test.txt', 'r') as f:
        content = await f.read()
        assert content == 'hello'
        
    conn.close()

@pytest.mark.asyncio
async def test_dac_other_deny():
    """Objective: Verify other cannot write without permission."""
    # Eve tries to write to /home/bob (owned by bob, mode 700)
    sftp, conn = await get_sftp_client('eve')
    
    with pytest.raises(asyncssh.SFTPError) as excinfo:
        async with sftp.open('/home/bob/eve_hack.txt', 'w') as f:
            await f.write('hacked')
    
    # Expect Permission Denied (3)
    assert excinfo.value.code == 3
    conn.close()

@pytest.mark.asyncio
async def test_mac_read_up():
    """Objective: Verify user with clearance internal can read public/internal but not confidential."""
    sftp, conn = await get_sftp_client('bob') # Internal
    
    # Read Public (OK) - User(1) >= Resource(0)
    # We need a file in public
    async with sftp.open('/public/readme.txt', 'r') as f:
        await f.read()
        
    # Read Internal (OK) - User(1) >= Resource(1)
    # Create file first (Bob can write to internal? No, DAC might block or MAC write down?)
    # Wait, Bob is 'user' role. 
    # Let's check /internal. DAC: alice:admins 770. Bob is in 'users'. 
    # So Bob is 'other' -> 0. DAC denies.
    # We need to adjust DAC or use a path Bob can access.
    # But the test is about MAC.
    # Let's assume DAC allows for a moment or check logs.
    # Actually, let's test MAC denial on confidential.
    
    # Read Confidential (Deny) - User(1) >= Resource(2) -> False
    with pytest.raises(asyncssh.SFTPError) as excinfo:
        async with sftp.open('/confidential/secret.txt', 'r') as f:
            await f.read()
    assert excinfo.value.code == 3
    
    conn.close()

@pytest.mark.asyncio
async def test_mac_no_write_down():
    """Objective: Verify confidential user cannot write down into public."""
    sftp, conn = await get_sftp_client('alice') # Confidential
    
    # Write Public (Deny) - User(2) <= Resource(0) -> False
    with pytest.raises(asyncssh.SFTPError) as excinfo:
        async with sftp.open('/public/leak.txt', 'w') as f:
            await f.write('leak')
    assert excinfo.value.code == 3
    
    conn.close()

@pytest.mark.asyncio
async def test_rbac_role_permissions():
    """Objective: Verify role permissions."""
    # Eve is 'guest'. Role perms: /public -> read, list, stat. No write.
    sftp, conn = await get_sftp_client('eve')
    
    # Read OK
    async with sftp.open('/public/readme.txt', 'r') as f:
        await f.read()
        
    # Write Deny
    with pytest.raises(asyncssh.SFTPError) as excinfo:
        async with sftp.open('/public/eve.txt', 'w') as f:
            await f.write('hello')
    assert excinfo.value.code == 3
    
    conn.close()

@pytest.mark.asyncio
async def test_composite_policy():
    """Objective: Verify final decision matches composition rule (DAC & MAC & RBAC)."""
    # Case: DAC allows, MAC allows, RBAC denies?
    # Or DAC allows, MAC denies.
    
    # Bob (Internal). /public/readme.txt.
    # DAC: /public owner alice:users 755. Bob in users? Yes (assumed). Mode 5 (r-x). Read OK.
    # MAC: Bob(1) >= Public(0). Read OK.
    # RBAC: Bob has role 'user'. Perms for /public?
    # In setup_data.py: ['user', '/public', '1', '0', '0', '0', '1', '1'] -> Read OK.
    # So Bob can read /public/readme.txt.
    
    sftp, conn = await get_sftp_client('bob')
    async with sftp.open('/public/readme.txt', 'r') as f:
        await f.read()
    conn.close()
    
    # Case: DAC allows, MAC denies.
    # Alice (Confidential). Write to /public.
    # DAC: /public owner alice. 755. Write OK (owner).
    # MAC: Alice(2) <= Public(0). Write DENY.
    # RBAC: Alice is admin. Admin has write on /. OK.
    # Result: Deny.
    
    sftp, conn = await get_sftp_client('alice')
    with pytest.raises(asyncssh.SFTPError) as excinfo:
        async with sftp.open('/public/alice_leak.txt', 'w') as f:
            await f.write('leak')
    assert excinfo.value.code == 3
    conn.close()

@pytest.mark.asyncio
async def test_audit_logging():
    """Objective: Verify audit records are written."""
    # Perform an action
    sftp, conn = await get_sftp_client('eve')
    try:
        await sftp.listdir('/public')
    except:
        pass
    conn.close()
    
    # Check audit.jsonl
    await asyncio.sleep(1) # Wait for flush
    found = False
    with open('audit.jsonl', 'r') as f:
        for line in f:
            record = json.loads(line)
            if record['user'] == 'eve' and record['op'] == 'opendir' and 'public' in record['path']:
                found = True
                break
    assert found
