# Computer Security Project: SFTP over SSH

This project is an implementation of a secure SFTP server built on top of the AsyncSSH transport layer. [cite_start]The server implements SFTP v3 and enforces Discretionary Access Control (DAC), Mandatory Access Control (MAC), and Role-Based Access Control (RBAC)[cite: 2, 6].

[cite_start]This server is built using Python 3 and `asyncssh`[cite: 22].

## 👥 Team Roles & Responsibilities

This project is divided among 7 team members:

* **Person 1 (Lead):** `server/server.py`
    * Manages the Git repository.
    * Implements the core server skeleton, SSH transport, and SFTP packet loop.
    * Refactors the code and integrates all other modules.
* **Person 2:** `client/client.py`
    * [cite_start]Implements the SFTP client CLI with all required commands (`pwd`, `ls`, `mkdir`, `get`, `put`, `stat`) [cite: 35, 146-159].
* **Person 3:** `server/auth.py` & `data/users.json`
    * [cite_start]Implements secure password verification (e.g., `hashlib.scrypt`)[cite: 28].
    * [cite_start]Loads and manages the static user authentication file[cite: 101].
* **Person 4:** `server/server.py`
    * Implements the server-side logic for **read/stat** operations (REALPATH, STAT, LSTAT, FSTAT, OPENDIR, READDIR, OPEN (read-only), CLOSE).
* **Person 5:** `server/server.py`
    * Implements the server-side logic for **write** operations (MKDIR, OPEN (write/create), WRITE, CLOSE).
* **Person 6:** `server/policy.py` & `data/`
    * [cite_start]Implements the **DAC** and **RBAC** authorization logic within the `authorize` gate[cite: 30, 64, 67].
    * [cite_start]Manages `user_roles.json`, `role_perms.csv`, and `dac_owners.csv`[cite: 103, 104, 107].
* **Person 7:** `server/policy.py`, `tests/`, `CTF_writeup.pdf`
    * [cite_start]Implements the **MAC** authorization logic ("no read up, no write down")[cite: 30, 66].
    * [cite_start]Implements the automated `pytest` tests for AuthN/AuthZ[cite: 36, 86].
    * [cite_start]Designs and documents the CTF[cite: 37, 161].

---

## 🚀 How to Run

### 1. Install Dependencies

This project requires the `asyncssh` library.

```bash
pip install asyncssh
