# SecPwdMgr - Secure Password Manager

```python
   _____           ____               ____  ___            
  / ___/___  _____/ __ \_      ______/ /  |/  /___ ______  
  \__ \/ _ \/ ___/ /_/ / | /| / / __  / /|_/ / __ `/ ___/  
 ___/ /  __/ /__/ ____/| |/ |/ / /_/ / /  / / /_/ / /  
/____/\___/\___/_/     |__/|__/\__,_/_/  /_/\__, /_/  
                                           /____/  
```

[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=my-spm_spm&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=my-spm_spm) [![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=my-spm_spm&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=my-spm_spm) [![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=my-spm_spm&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=my-spm_spm) [![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=my-spm_spm&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=my-spm_spm) [![Bugs](https://sonarcloud.io/api/project_badges/measure?project=my-spm_spm&metric=bugs)](https://sonarcloud.io/summary/new_code?id=my-spm_spm) [![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=my-spm_spm&metric=code_smells)](https://sonarcloud.io/summary/new_code?id=my-spm_spm) [![Duplicated Lines (%)](https://sonarcloud.io/api/project_badges/measure?project=my-spm_spm&metric=duplicated_lines_density)](https://sonarcloud.io/summary/new_code?id=my-spm_spm) [![Technical Debt](https://sonarcloud.io/api/project_badges/measure?project=my-spm_spm&metric=sqale_index)](https://sonarcloud.io/summary/new_code?id=my-spm_spm)  
[![SonarQube Cloud](https://sonarcloud.io/images/project_badges/sonarcloud-light.svg)](https://sonarcloud.io/summary/overall?id=my-spm_spm&branch=master)

A secure, command-line password manager designed for managing password entries and securely storing them in a vault.

This project is available at [GitHub (https://github.com/lrlnt/SecPwdMgr.git)](https://github.com/lrlnt/SecPwdMgr.git).

## Features

### Functionality

- **Create Entries** - Add new password entries with service, username, and password
- **List and Get Entries** - View and copy passwords to clipboard for all stored entries
- **Update Entries** - Modify existing entries (service, username, or password)
- **Delete Entries** - Remove entries from the vault
- **Search Entries** - Find entries by service or username
- **Password Generator** - Generate secure random passwords with customizable options
- **Exit** - Automatic save on interrupt signals (SIGINT/SIGTERM)

### Security

- **AES-256-GCM Encryption** - Industry-standard encryption for data at rest
- **PBKDF2 Key Derivation** - 300,000 iterations for master password hashing
- **HMAC-SHA256 Authentication** - Ensures data integrity and authenticity
- **Secure File Permissions** - Files created with 0600 permissions (owner-only access)
- **Symlink Protection** - Prevents symlink attacks
- **Atomic Writes** - Prevents data corruption during saves
- **Secure Cleanup** - Sensitive data cleared from memory on exit

## Requirements

- Python 3.8 or higher
- External dependencies (see `requirements.txt`)

## Installation

1. **Clone the repository**

   ```sh
   git clone https://github.com/lrlnt/SecPwdMgr.git
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

### First-Time Run - create vault

1. **Set a strong master password** (prompted).
2. **(Optional)** Add example entries, or start managing your own.

### Open vault

```sh
python SecPwdMgr.py myvault
```

- Eter your master password.
- Use the interactive menu to add, list, update, delete, search, retrieve passwords or generate temporary password.
- Generated or retrieved passwords are copied automatically to your clipboard.

---

## Security Advice

- Pick a strong, unique master password — it's never stored, only used to unlock your vault.
- Backup your vault file securely.
- Vault files are only as safe as your master password and filesystem security!

---

## License

This project is licensed under the [Apache License 2.0](https://www.apache.ßorg/licenses/LICENSE-2.0).

---
