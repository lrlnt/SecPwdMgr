[![SonarQube Cloud](https://sonarcloud.io/images/project_badges/sonarcloud-light.svg)](https://sonarcloud.io/summary/new_code?id=my-spm_spm) [![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=my-spm_spm&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=my-spm_spm)
# SecPwdMgr - Secure Password Manager

A secure, command-line password manager with AES-256-GCM encryption, designed for secure storage and management of password entries.

## Features

### Security
- **AES-256-GCM Encryption** - Industry-standard encryption for data at rest
- **PBKDF2 Key Derivation** - 300,000 iterations for master password hashing
- **HMAC-SHA256 Authentication** - Ensures data integrity and authenticity
- **Secure File Permissions** - Files created with 0600 permissions (owner-only access)
- **Symlink Protection** - Prevents symlink attacks
- **Atomic Writes** - Prevents data corruption during saves
- **Secure Cleanup** - Sensitive data cleared from memory on exit

### Functionality
- **Create Entries** - Add new password entries with service, username, and password
- **List Entries** - View all stored entries
- **Update Entries** - Modify existing entries (service, username, or password)
- **Delete Entries** - Remove entries from the vault
- **Search Entries** - Find entries by service or username
- **Get Password** - Retrieve and copy password to clipboard
- **Password Generator** - Generate secure random passwords with customizable options
- **Safe Exit** - Automatic save on interrupt signals (SIGINT/SIGTERM)

## Requirements

- Python 3.8 or higher
- External dependencies (see `requirements.txt`)

## Installation

1. **Clone the repository**
   ```sh
   git clone https://github.com/yourusername/SecPwdMgr.git
   cd SecPwdMgr
   ```

2. **Create and activate a virtual environment (recommended)**
   ```sh
   python3 -m venv venv
   source venv/bin/activate   # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```sh
   pip install -r requirements.txt
   ```

---

## Usage

### Basic Usage

```sh
python SecPwdMgr.py <vault_file>
```
- If `<vault_file>` does not exist, you'll be prompted to create one and set a master password.
- The `.spm` extension is recommended (it will be auto-added if missing):

```sh
python SecPwdMgr.py myvault.spm
# or
python SecPwdMgr.py myvault  # becomes myvault.spm
```

### First-Time Run

1. **Set a strong master password** (prompted).
2. **(Optional)** Add example entries, or start managing your own.

---

## Example Flow

```sh
python SecPwdMgr.py myvault
```
- Set or enter your master password.
- Use the interactive menu to add, list, update, delete, search, or retrieve passwords.
- Generated or retrieved passwords are copied automatically to your clipboard.

---

## Security Advice

- Pick a strong, unique master password—it's never stored, only used to unlock your vault.
- Backup your vault file securely.
- Vault files are only as safe as your master password and filesystem security!

---

## License

[MIT License](LICENSE)

---
