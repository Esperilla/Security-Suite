# 🔐 Security Suite - Java OOP

[![Java](https://img.shields.io/badge/Java-17%2B-orange?logo=openjdk)](https://openjdk.org/)
[![Status](https://img.shields.io/badge/Status-Complete-green.svg)]()

A Java console application that provides security tools for password management and file encryption, developed using **Object-Oriented Programming** principles.

## 📋 Table of Contents

- [Features](#-features)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Usage](#-usage)
- [Architecture](#-architecture)
- [Security](#-security)
- [Project Structure](#-project-structure)

---

## ✨ Features

### 🔑 Password Manager (Vault)
- **Secure storage** of secrets encrypted with PBKDF2-HMAC-SHA256 and AES-256-GCM
- **Smart search** using the Levenshtein algorithm (typo tolerance)
- Complete CRUD operations (Create, Read, Update, Delete)
- **Strong password policy** (minimum 8 characters, uppercase letters, numbers, and symbols)
- Master password changes with automatic re-encryption
- Case-insensitive unique names; secret values preserve spaces
- Bounded name/value limits and bounded Levenshtein search prevent excessive resource use

### 🔒 File Encryptor
- Encrypts and decrypts individual files using the master password
- `.locked` extension for encrypted files
- Writes the destination atomically and deletes the original only after a successful conversion
- Refuses to overwrite an existing destination (the `.locked` check is case-insensitive)
- Validates the published output before deleting the source

### 📊 Audit System
- **Event log** recording all operations
- Severity levels: INFO, WARN, ERROR
- Automatic log retention (7 days)
- No sensitive values are logged (only secret names)

### 🛡️ Implemented Security
- **AES-256-GCM** with a random IV for every operation
- Versioned `SSV2` format with a random PBKDF2 salt and a magic/version/salt header authenticated as AES-GCM AAD
- Legacy SHA-256 data remains readable; migration is best-effort, preserves a non-overwritten `.legacy.bak`, and never blocks a successful login
- Password input hidden in the terminal
- Password cleanup in memory (`char[]`)
- Authentication attempt limit

---

## 📦 Requirements

- **Java 17** or later
- **Real terminal** (PowerShell, CMD, Bash)
  > ⚠️ **Does not work from IDE integrated terminals** because it uses `System.console()` to hide passwords.

---

## 🚀 Installation

### 1. Clone the repository

```bash
git clone https://github.com/Esperilla/Suite-de-Seguridad.git
cd Suite-de-Seguridad
```

### 2. Compile the project

```powershell
# Windows (PowerShell)
javac -d out src/models/*.java src/modules/*.java src/main/*.java
```

```bash
# Linux/Mac
javac -d out src/models/*.java src/modules/*.java src/main/*.java
```

### 3. Run

```powershell
# Windows (PowerShell)
java -cp out main.Main
```

Dependency-free critical tests:

```powershell
javac --release 17 -d out src\models\*.java src\modules\*.java src\main\*.java tests\CriticalTests.java
java -cp out CriticalTests
```

```bash
# Linux/Mac
java -cp out main.Main
```

---

## 💻 Usage

### First Run

When running the application for the first time, you will be asked to create a **master password**:

```
--- SECURITY SUITE (JAVA OOP) ---

--- Initial Setup ---
Welcome. Create a master password.

Password requirements:
  • Minimum 8 characters
  • At least one uppercase letter
  • At least one number
  • At least one special character (!@#$%^&* etc.)

New password: ********
Confirm password: ********
System configured successfully!
```

### Main Menu

```
--- Main Menu ---
1. Password Manager
2. File Encryptor
3. Exit
>
```

### Password Manager

```
--- Password Manager ---
1. Add secret
2. View secret
3. List secrets
4. Delete secret
5. Update secret
6. Change master password
7. Save and Return
>
```

**Smart search**: You do not need to remember the exact secret name. The system finds matches even when the search contains typos:

```
Search secret: gmai

✔ Secret found: Gmail
Value: my_secure_password
```

### File Encryptor

```
--- File Encryptor ---
1. Encrypt file
2. Decrypt file
3. Return
>
```

> 💡 **Tip**: Use `/` instead of `\` in file paths:
> ```
> File path: C:/Users/user/document.txt
> ```

---

## 🏗️ Architecture

The project implements a modular architecture based on **Object-Oriented Programming**:

```
┌─────────────────────────────────────────────────────────┐
│                      Main.java                          │
│                     (Entry point)                       │
└──────────────────────────┬──────────────────────────────┘
                           │
            ┌──────────────┴──────────────┐
            ▼                             ▼
┌───────────────────────┐     ┌───────────────────────┐
│      VaultModule      │     │      FileModule       │
│   (Password Manager)  │     │   (File Encryptor)    │
└───────────┬───────────┘     └───────────┬───────────┘
            │                             │
            └──────────────┬──────────────┘
                           ▼
              ┌─────────────────────────┐
              │       BaseModule        │
              │    (Abstract class)     │
              │   - Polymorphism        │
              │   - Inheritance         │
              └─────────────────────────┘
                           │
                           ▼
              ┌─────────────────────────┐
              │     EncryptionUtils      │
              │   - AES-GCM 256 bits     │
              │   - Random IV            │
              └─────────────────────────┘
```

### Applied OOP Concepts

| Concept | Implementation |
|---|---|
| **Inheritance** | `BaseModule` → `VaultModule`, `FileModule` |
| **Polymorphism** | `execute()` method in each module |
| **Abstraction** | Abstract `BaseModule` class |
| **Encapsulation** | Private attributes with getters |
| **Composition** | `Main` uses `Vault` and `VaultStorage` |
| **Serialization** | `Vault` implements `Serializable` |

---

## 🔒 Security

### AES-GCM Encryption

The system uses **AES-256-GCM** (Galois/Counter Mode) for encryption:

| Feature | Description |
|---|---|
| **Algorithm** | AES-256 |
| **Mode** | GCM (built-in authentication) |
| **IV** | 12 random bytes per operation |
| **Authentication tag** | 128 bits |

### Password Policy

Master passwords must meet the following requirements:
- ✅ Minimum 8 characters
- ✅ At least one uppercase letter
- ✅ At least one number
- ✅ At least one special character (`!@#$%^&*()-_=+[]{}|;:'',.<>?/~``)

### Attack Protection

- **Brute force**: Three-attempt limit for changing the master password
- **Login**: Three-attempt limit; an existing legacy vault is backed up and atomically migrated after successful authentication
- **Memory**: Passwords cleared with `Arrays.fill(arr, '\0')`
- **Replay**: A unique IV is generated for every encryption operation
- **Audit log**: Stored at `logs/audit.log`; messages are sanitized to prevent forged log lines
- Persistent files are owner-restricted when supported, and the audit log rotates at 1 MiB

### Vault format, migration, and persistence

New vaults use `SSV2`: PBKDF2-HMAC-SHA256 (210,000 iterations), a fresh 16-byte salt,
and AES-256-GCM with a fresh 12-byte IV and 128-bit tag. The magic header, version,
and salt are authenticated as AES-GCM AAD; unknown versions and altered metadata are
rejected. Legacy SHA-256 vaults and files remain readable, but legacy `.locked` files
must be decrypted and encrypted again to use the current format.

On legacy login, decryption and vault validation happen before migration. The original
file is copied to `boveda.dat.legacy.bak` only if that backup does not already exist.
The new file is written to a temporary file, decrypted, reconstructed, and compared
before publication. A migration failure is logged and shown as a warning, preserves
the legacy vault, and does not deny login; migration can be retried later. The backup
is retained as an explicit recovery copy and is never overwritten automatically.

Vault changes are tracked as pending changes and saved when the user selects
“Save and Return” or exits. EOF also attempts a save, and save errors are reported
instead of being treated as a successful clean exit. Secret names are trimmed and
unique without case sensitivity (`Locale.ROOT`); secret values and passwords are
never trimmed. Names, values, and searches have practical maximum lengths.
Persistence uses a forced temporary write, atomic move when available, validation,
and a best-effort parent-directory synchronization. Large files are read into
memory with `readAllBytes()`, so file sizes should remain within available memory.

---

## 📁 Project Structure

```
Security-Suite/
├── 📄 README.md                    # This file
├── 📄 Security-Suite.iml      # IntelliJ IDEA configuration
├── 📁 src/
│   ├── 📁 main/
│   │   └── 📄 Main.java            # Application entry point
│   ├── 📁 models/
│   │   ├── 📄 Vault.java                # In-memory secret store
│   │   ├── 📄 VaultStorage.java         # Encrypted persistence
│   │   ├── 📄 EncryptionUtils.java      # Cryptographic functions
│   │   ├── 📄 AuditLog.java             # Logging system
│   │   └── 📄 FileSecurity.java         # Filesystem permissions and synchronization
│   └── 📁 modules/
│       ├── 📄 BaseModule.java           # Abstract base class
│       ├── 📄 VaultModule.java          # Password manager
│       └── 📄 FileModule.java           # File encryptor
├── 📁 tests/                       # Dependency-free critical tests
├── 📁 logs/                        # Local audit logs (ignored by Git)
└── 📄 boveda.dat                   # Encrypted vault (generated at runtime)
```

---

## 🎓 Academic Context

- Practical application of OOP in Java
- Implementation of modern cryptography
- Modular software design
- Secure programming best practices

---

## 👤 Authors

- GitHub: [@Esperilla](https://github.com/Esperilla)
---
