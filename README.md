# Dark matter - simple vault CLI utility with GPG encryption

Dark Matter is a command-line tool for secure file management using GPG encryption. It provides a robust way to vault, manage, and track encrypted files while maintaining security through GPG key verification.

## Features

- Secure file storage with GPG encryption
- File versioning and tracking
- Easy file management (add, update, remove, export)
- Key verification and diagnostics
- SQLite-based database for file tracking
- Command-line interface for all operations

## Prerequisites

- GPG (GnuPG) installed and configured
- A valid GPG key pair
- Rust development environment (for building from source)

## Installation

1. Clone the repository
2. Install gpg dependencies
   ```
   sudo apt-get install libgpgme-dev
   ```
4. Build the project using Cargo:
   ```bash
   cargo build --release
   ```
5. The binary will be available in `target/release/dark-matter`

## Usage

### Initialize Vault

Get list of gpg keys

```bash
gpg --list-keys
```

Create your GPG key

```bash
gpg --full-generate-key
```

Validate your GPG key:
   ```bash
   dark-matter keys validate <key-hash>
   ```

Before using Dark Matter, you need to initialize vault it with your GPG key hash:

```bash

# create dir
mkdir vault
cd vault
dark-matter init <key-hash>
```

The key hash can be obtained from your GPG keyring. This creates a new vault and configures Dark Matter for use with your key.

### File Management

#### Add a File

To add a new file to the vault:
```bash
dark-matter file add <filename>
```

The file will be encrypted using your GPG key and stored in the vault.

### Listing Files

View all files in the vault:
```bash
dark-matter file list
```

#### Update a File

Update an existing file in the vault:
```bash
dark-matter file update <filename>
```

This creates a new encrypted version of the file while maintaining version history.

#### Remove a File

Remove a file from the vault:
```bash
dark-matter file remove <filename>
```

#### Export a File

Export a file from the vault (decrypts the file to its original path):
```bash
dark-matter file export <filename>
```

To export to the current directory:
```bash
dark-matter file export <filename> --relative
```

To skip confirmation for overwriting files:
```bash
dark-matter file export <filename> --yes
```

### Key Diagnostics

Verify GPG key configuration and system status:
```bash
dark-matter keys validate <key-hash>
```

## Error Handling

Dark Matter provides detailed error messages for common issues:

- Database not found or already exists
- File not found or already exists
- GPG key verification failures
- Database operation errors
- I/O errors

## Security Considerations

- All files are encrypted using GPG
- Key verification is performed for all operations
- Database is protected against unauthorized access
- Original files should be securely deleted after adding to the vault

## License

This software is provided under a dual license:

1. Source-Available Evaluation License (Default)
   - Allows viewing and personal, non-commercial evaluation
   - No modification, redistribution, or commercial use permitted

2. Commercial License (By Agreement)
   - Required for commercial use, modifications, or redistribution
   - Contact the author for licensing terms

See LICENSE.txt for complete terms.

## Contact

For commercial licensing inquiries or technical support:

- Author: Alexey Nikandrov
- Email: classx@gmail.com

## Contributing

As this is a proprietary, source-available project, contributions are not accepted without prior agreement. Please contact the author for collaboration opportunities.
