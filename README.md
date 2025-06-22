# Dark Matter - Secure File Management System

Dark Matter is a command-line tool for secure file management using GPG encryption. It provides a robust way to store, manage, and track encrypted files while maintaining security through GPG key verification.

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
2. Build the project using Cargo:
   ```bash
   cargo build --release
   ```
3. The binary will be available in `target/release/dark-matter`

## Usage

### Initialize Storage

Before using Dark Matter, you need to initialize it with your GPG key hash:

```bash
dark-matter init <key-hash>
```

The key hash can be obtained from your GPG keyring. This creates a new database and configures Dark Matter for use with your key.

### Adding Files

To add a new file to secure storage:

```bash
dark-matter add <filename>
```

The file will be encrypted using your GPG key and stored in the Dark Matter database.

### Listing Files

View all files in storage:

```bash
dark-matter list
```

### Updating Files

Update an existing file in storage:

```bash
dark-matter update <filename>
```

This creates a new encrypted version of the file while maintaining version history.

### Removing Files

Remove a file from storage:

```bash
dark-matter remove <filename>
```

### Exporting Files

Export a file from storage (decrypts to original form):

```bash
dark-matter export <filename>
```

### Diagnostic Tools

Verify GPG key configuration and system status:

```bash
dark-matter diagnose <key-hash>
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
- Original files should be securely deleted after adding to Dark Matter

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
