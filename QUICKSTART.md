# Quick Start Guide - SFTP Server

## Prerequisites

1. Python 3.8+ installed
2. pip package manager
3. OpenSSH client (for generating host key)

## Setup Steps

### 1. Install Dependencies

```bash
pip install asyncssh pytest
```

### 2. Generate Host Key (Already Done!)

The SSH host key has already been generated in `server/ssh_host_ed25519_key`.

If you need to regenerate it:
```bash
cd server
ssh-keygen -t ed25519 -N "" -f ssh_host_ed25519_key
cd ..
```

### 3. Start the Server

```bash
cd server
python server.py
```

You should see:
```
[Policy] Loaded 3 users from .../data/users.json
[Policy] Loaded user roles from .../data/user_roles.json
[Policy] Loaded role permissions from .../data/role_perms.csv
[Policy] Loaded MAC labels from .../data/mac_labels.json
[Policy] Loaded DAC owners from .../data/dac_owner.json
Listening on port 8022...
```

### 4. Test with Client

Open a **new terminal** and run:

```bash
python client/client.py localhost alice password123 8022
```

**Available commands:**
```
sftp> pwd                # Print working directory
sftp> ls                 # List files
sftp> ls secret_storage  # List directory contents
sftp> stat Test.txt      # Show file attributes
sftp> get Test.txt       # Download file
sftp> get secret_storage/flag.txt    # Get the flag!
sftp> quit               # Exit
```

## Test Users

| Username | Password | Role | Can Access Flag? |
|----------|----------|------|------------------|
| alice | password123 | admin | ✅ YES |
| bob | password456 | analyst | ❌ NO (blocked by DAC/MAC/RBAC) |
| eve | password789 | intern | ❌ NO (blocked by all models) |

## Getting the Flag

Only Alice can access the CTF flag:

```bash
python client/client.py localhost alice password123 8022
```

Then in the SFTP session:
```
sftp> get secret_storage/flag.txt
Downloaded: secret_storage/flag.txt -> flag.txt
sftp> quit
```

On your local machine:
```bash
cat flag.txt
```

Output: `FLAG{access_control_is_not_optional_123}`

## Testing Other Users

**Test Bob (should fail):**
```bash
python client/client.py localhost bob password456 8022
sftp> get secret_storage/flag.txt
# Error: Permission denied
```

**Test Eve (should fail):**
```bash
python client/client.py localhost eve password789 8022
sftp> get secret_storage/flag.txt
# Error: Permission denied
```

## Run Automated Tests

```bash
pytest tests/ -v
```

Expected output:
```
tests/test_auth.py::test_success_correct_password_default_params PASSED
tests/test_policy.py::TestDAC::test_owner_can_read_own_file PASSED
tests/test_policy.py::TestDAC::test_other_cannot_read_owner_file PASSED
tests/test_policy.py::TestMAC::test_no_read_up_confidential PASSED
tests/test_policy.py::TestRBAC::test_admin_can_read_flag PASSED
tests/test_policy.py::TestComposite::test_alice_can_access_flag PASSED
... and more
```

## View Audit Logs

After making some requests, view the audit log:

**Windows PowerShell:**
```powershell
Get-Content server/audit.jsonl | Select-Object -Last 10
```

**Linux/macOS:**
```bash
tail -n 10 server/audit.jsonl
```

**Python:**
```python
import json
with open('server/audit.jsonl') as f:
    for line in f:
        print(json.loads(line))
```

## Troubleshooting

### Server won't start - "No host key"
```bash
cd server
ssh-keygen -t ed25519 -N "" -f ssh_host_ed25519_key
cd ..
```

### Server won't start - "Failed to load policy data"
Make sure all files in `data/` directory exist:
- users.json
- user_roles.json
- role_perms.csv
- mac_labels.json
- dac_owner.json

### Client can't connect - "Connection refused"
- Make sure server is running
- Check that you're using port 8022 (default)
- Try: `python client/client.py localhost alice password123 8022`

### "Permission denied" when accessing files
- Check which user you're logged in as
- Bob and Eve cannot access secret_storage/flag.txt (this is expected!)
- Only Alice (admin) can access the flag

### Import errors when running tests
```bash
# Make sure you're in the project root directory
cd C:\Users\Ember\Desktop\sftp_server

# Run tests
pytest tests/ -v
```

## What's Next?

1. ✅ Server is running
2. ✅ Client can connect
3. ✅ Access control is enforced
4. ✅ Flag is protected
5. ✅ Tests pass
6. ✅ Documentation complete

**Read the full documentation:**
- `README.md` - Complete project documentation
- `CTF_writeup.md` - Security analysis and attack scenarios
- `COMPLETION_SUMMARY.md` - What was implemented

**Project is ready for submission! 🎉**
