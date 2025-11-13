# Computer Security Project: SFTP over SSH

This project is an implementation of a secure SFTP server built on top of the AsyncSSH transport layer. The server implements SFTP v3 and enforces Discretionary Access Control (DAC), Mandatory Access Control (MAC), and Role-Based Access Control (RBAC).

 This server is built using Python 3 and `asyncssh`.

## 👥 Team Roles & Responsibilities

This project is divided among 7 team members:

* **Person 1 (Lead):** `server/server.py`
    * Manages the Git repository.
    * Implements the core server skeleton, SSH transport, and SFTP packet loop.
    * Refactors the code and integrates all other modules.
* **Person 2:** `client/client.py`
    * Implements the SFTP client CLI with all required commands (`pwd`, `ls`, `mkdir`, `get`, `put`, `stat`).
* **Person 3:** `server/auth.py` & `data/users.json`
    *  Implements secure password verification (e.g., `hashlib.scrypt`).
    *  Loads and manages the static user authentication file.
* **Person 4:** `server/server.py`
    * Implements the server-side logic for **read/stat** operations (REALPATH, STAT, LSTAT, FSTAT, OPENDIR, READDIR, OPEN (read-only), CLOSE).
* **Person 5:** `server/server.py`
    * Implements the server-side logic for **write** operations (MKDIR, OPEN (write/create), WRITE, CLOSE).
* **Person 6:** `server/policy.py` & `data/`
    *  Implements the **DAC** and **RBAC** authorization logic within the `authorize` gate.
    *  Manages `user_roles.json`, `role_perms.csv`, and `dac_owners.csv`.
* **Person 7:** `server/policy.py`, `tests/`, `CTF_writeup.pdf`
    *  Implements the **MAC** authorization logic ("no read up, no write down").
    *  Implements the automated `pytest` tests for AuthN/AuthZ.
    *  Designs and documents the CTF.

---

## 🚀 How to Run

### 1. Install Dependencies

This project requires the `asyncssh` library.

```bash
pip install asyncssh

