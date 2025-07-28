use clap::{Parser, Subcommand};
use gpgme::{Context, Protocol};
use rusqlite::Connection;
use std::fs;
use std::io::{self, Write};
use std::path::Path;

const DB_NAME: &str = "dm-vault.db";
const GPG_KEY_HASH_CONFIG: &str = "gpg_key_hash";

#[derive(Parser)]
#[command(name = "dark-matter")]
#[command(about = "Dark matter - simple vault CLI utility with GPG encryption")]
#[command(version = "1.0.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Init new vault in current directory
    Init {
        /// Hash GPG key for encryption
        key_hash: String,
    },
    /// File management operations
    File {
        #[command(subcommand)]
        action: FileCommands,
    },
    /// Secret management operations
    Secret {
        #[command(subcommand)]
        action: SecretsCommands,
    },
    /// Key validation and diagnostics
    Keys {
        #[command(subcommand)]
        action: KeysCommands,
    },
}

#[derive(Subcommand)]
pub enum SecretsCommands {
    /// Add new secret to vault
    Add {
        /// Name of the secret
        name: String,
        /// New value for the secret
        value: String,
        /// Optional tags for the secret. Comma-separated.
        #[arg(short, long, default_value = "")]
        tags: String,
    },
    /// List all secrets in vault
    List {
        /// Optional tags for the secret. Comma-separated.
        #[arg(short, long, default_value = "")]
        tags: String,
    },
    /// Update existing secret in vault
    Update {
        /// Name of the secret to update
        name: String,
        /// New value for the secret
        value: String,
        /// Optional tags for the secret. Comma-separated.
        #[arg(short, long, default_value = "")]
        tags: String,
    },
    /// Remove secret from vault
    Remove {
        /// Name of the secret to remove
        name: String,
    },
    /// Show secret from vault
    Show {
        /// Name of the secret to show
        name: String,
    },
}

#[derive(Subcommand)]
pub enum KeysCommands {
    /// Validate GPG key for use with dark-matter
    Validate {
        /// Hash of GPG key to validate
        key_hash: String,
    },
}

#[derive(Subcommand)]
pub enum FileCommands {
    /// Add new file to vault
    Add {
        /// Absolute path to file for adding
        filename: String,
    },
    /// List all files in vault
    List,
    /// Update existing file in vault
    Update {
        /// Absolute path to file for updating
        filename: String,
    },
    /// Remove file from vault
    Remove {
        /// Absolute path to file for removing
        filename: String,
    },
    /// Export and decrypt file from vault
    Export {
        /// Absolute path to file for exporting
        filename: String,

        /// Export to current directory
        #[arg(short, long, default_value_t = false)]
        relative: bool,

        /// Export to current directory
        #[arg(short = 'y', long = "yes", default_value_t = false)]
        confirm: bool,
    },
}

#[derive(Debug)]
enum DmError {
    DatabaseNotFound,
    DatabaseAlreadyExists,
    FileNotFound(String),
    GpgKeyNotFound(String),
    FileAlreadyExists(String),
    FileNotInStorage(String),
    SecretNotInStorage(String),
    DatabaseError(rusqlite::Error),
    GpgError(gpgme::Error),
    IoError(io::Error),
}

impl std::fmt::Display for DmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DmError::DatabaseNotFound => {
                write!(f, "Error: database dm-vault.db not found. Please run 'dm init <gpg_key_hash>' to create a new vault.")
            }
            DmError::DatabaseAlreadyExists => write!(f, "Error: database dm-vault.db already exists. Please remove it or use a different directory."),
            DmError::FileNotFound(path) => write!(f, "Error: File '{}' not found", path),
            DmError::GpgKeyNotFound(hash) => {
                write!(f, "Error: GPG key '{}' not found", hash)
            }
            DmError::SecretNotInStorage(name) => {
                write!(f, "Error: Secret '{}' not found in vault", name)
            }
            DmError::FileAlreadyExists(path) => write!(
                f,
                "Error: File '{}' already exists in vault. Use 'dm update <filename>' to update it.",
                path
            ),
            DmError::FileNotInStorage(path) => {
                write!(f, "Error: File '{}' not found in vault", path)
            }
            DmError::DatabaseError(e) => write!(f, "Database error: {}", e),
            DmError::GpgError(e) => write!(f, "GPG error: {}", e),
            DmError::IoError(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for DmError {}

impl From<rusqlite::Error> for DmError {
    fn from(error: rusqlite::Error) -> Self {
        DmError::DatabaseError(error)
    }
}

impl From<gpgme::Error> for DmError {
    fn from(error: gpgme::Error) -> Self {
        DmError::GpgError(error)
    }
}

impl From<io::Error> for DmError {
    fn from(error: io::Error) -> Self {
        DmError::IoError(error)
    }
}

struct DataManager;

impl DataManager {
    fn init(key_hash: &str) -> Result<(), DmError> {
        // Check if database already exists
        if Path::new(DB_NAME).exists() {
            return Err(DmError::DatabaseAlreadyExists);
        }

        // Check if GPG key exists
        Self::verify_gpg_key(key_hash)?;

        // Create vault
        let conn = Connection::open(DB_NAME)?;

        conn.execute(
            "CREATE TABLE config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                body BLOB NOT NULL,
                tags TEXT DEFAULT ''
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE flist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                realpath TEXT NOT NULL UNIQUE,
                body BLOB NOT NULL
            )",
            [],
        )?;

        // Save hash of GPG key in configuration
        conn.execute(
            "INSERT INTO config (key, value) VALUES (?1, ?2)",
            rusqlite::params![GPG_KEY_HASH_CONFIG, key_hash],
        )?;

        println!("Vault initialized with GPG key: {}", key_hash);
        Ok(())
    }

    // secrets management methods
    fn add_secret(name: &str, value: &str, tags: &str) -> Result<(), DmError> {
        let conn = Self::open_database()?;

        // Check if secret already exists
        let count: i64 = conn.query_row(
            "SELECT COUNT(id) FROM secrets WHERE name = ?1",
            rusqlite::params![name],
            |row| row.get(0),
        )?;

        if count > 0 {
            return Err(DmError::FileAlreadyExists(name.to_string()));
        }

        // Encrypt the value
        let key_hash = Self::get_gpg_key_hash(&conn)?;
        let encrypted_value = Self::encrypt_content(value.as_bytes(), &key_hash)?;

        // Insert into database
        conn.execute(
            "INSERT INTO secrets (name, body, tags) VALUES (?1, ?2, ?3)",
            rusqlite::params![name, encrypted_value, tags],
        )?;

        println!("Secret '{}' successfully added", name);
        Ok(())
    }

    fn list_secrets(tags: &str) -> Result<(), DmError> {
        let conn = Self::open_database()?;

        let mut stmt = conn.prepare("SELECT name, tags FROM secrets ORDER BY name")?;
        let secret_iter = stmt.query_map([], |row| {
            let name: String = row.get(0)?;
            let tags: String = row.get(1)?;
            Ok((name, tags))
        })?;

        let mut secrets = Vec::new();
        for secret in secret_iter {
            let secret: (String, String) = secret?;
            if !tags.is_empty() {
                // Filter by tags if specified
                if !secret
                    .1
                    .split(',')
                    .any(|t| tags.split(',').any(|tag| tag.trim() == t.trim()))
                {
                    continue;
                }
            }
            secrets.push(secret);
        }

        if secrets.is_empty() {
            println!("No secrets found in vault");
        } else {
            println!("List of secrets in vault:");
            for (name, tags) in secrets {
                println!("  {} tags: {}", name, tags);
            }
        }
        Ok(())
    }

    fn update_secret(name: &str, value: &str, tags: &str) -> Result<(), DmError> {
        let conn = Self::open_database()?;

        // Check if secret exists
        let count: i64 = conn.query_row(
            "SELECT COUNT(id) FROM secrets WHERE name = ?1",
            rusqlite::params![name],
            |row| row.get(0),
        )?;

        if count == 0 {
            return Err(DmError::FileNotInStorage(name.to_string()));
        }

        // Encrypt the new value
        let key_hash = Self::get_gpg_key_hash(&conn)?;
        let encrypted_value = Self::encrypt_content(value.as_bytes(), &key_hash)?;

        // Update the secret
        if !tags.is_empty() {
            conn.execute(
                "UPDATE secrets SET body = ?1, tags = ?2 WHERE name = ?3",
                rusqlite::params![encrypted_value, tags, name],
            )?;
        } else {
            conn.execute(
                "UPDATE secrets SET body = ?1 WHERE name = ?2",
                rusqlite::params![encrypted_value, name],
            )?;
        }

        println!("Secret '{}' successfully updated", name);
        Ok(())
    }

    fn remove_secret(name: &str) -> Result<(), DmError> {
        let conn = Self::open_database()?;

        let rows_affected = conn.execute(
            "DELETE FROM secrets WHERE name = ?1",
            rusqlite::params![name],
        )?;

        if rows_affected == 0 {
            println!("Secret '{}' not found in vault", name);
        } else {
            println!("Secret '{}' successfully removed from vault", name);
        }
        Ok(())
    }

    fn show_secret(name: &str) -> Result<(), DmError> {
        let conn = Self::open_database()?;

        // Get the encrypted secret
        let encrypted_value: Vec<u8> = conn
            .query_row(
                "SELECT body FROM secrets WHERE name = ?1",
                rusqlite::params![name],
                |row| row.get(0),
            )
            .map_err(|_| DmError::SecretNotInStorage(name.to_string()))?;

        // Decrypt the secret
        let decrypted_value = Self::decrypt_content(&encrypted_value)?;

        println!("{}", String::from_utf8_lossy(&decrypted_value));
        Ok(())
    }

    // File management methods
    fn add(filename: &str) -> Result<(), DmError> {
        let conn = Self::open_database()?;
        let realpath = Self::get_absolute_path(filename)?;

        // Check if file exists
        if !Path::new(filename).exists() {
            return Err(DmError::FileNotFound(filename.to_string()));
        }

        // Check if file already added
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM flist WHERE realpath = ?1",
            rusqlite::params![&realpath],
            |row| row.get(0),
        )?;

        if count > 0 {
            return Err(DmError::FileAlreadyExists(realpath));
        }

        // Read file content
        let content = fs::read(filename)?;

        // Get GPG key hash from configuration
        let key_hash = Self::get_gpg_key_hash(&conn)?;

        // Encrypt content
        let encrypted_content = Self::encrypt_content(&content, &key_hash)?;

        // Save to vault
        conn.execute(
            "INSERT INTO flist (realpath, body) VALUES (?1, ?2)",
            rusqlite::params![&realpath, &encrypted_content],
        )?;

        println!("File '{}' successfully added to vault", filename);
        Ok(())
    }

    fn list() -> Result<(), DmError> {
        let conn = Self::open_database()?;

        let mut stmt = conn.prepare("SELECT realpath FROM flist ORDER BY realpath")?;
        let file_iter = stmt.query_map([], |row| {
            let path: String = row.get(0)?;
            Ok(path)
        })?;

        let mut files = Vec::new();
        for file in file_iter {
            files.push(file?);
        }

        if files.is_empty() {
            println!("Vault is empty");
        } else {
            println!("List of files in vault:");
            for file in files {
                println!("  {}", file);
            }
        }

        Ok(())
    }

    fn update(filename: &str) -> Result<(), DmError> {
        let conn = Self::open_database()?;
        let realpath = Self::get_absolute_path(filename)?;

        // Check if file exists on disk
        if !Path::new(filename).exists() {
            return Err(DmError::FileNotFound(filename.to_string()));
        }

        // Check if file exists in vault
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM flist WHERE realpath = ?1",
            rusqlite::params![&realpath],
            |row| row.get(0),
        )?;

        if count == 0 {
            return Err(DmError::FileNotInStorage(realpath));
        }

        // Read new file content
        let content = fs::read(filename)?;

        // Get GPG key hash from configuration
        let key_hash = Self::get_gpg_key_hash(&conn)?;

        // Encrypt content
        let encrypted_content = Self::encrypt_content(&content, &key_hash)?;

        // Update record in vault
        conn.execute(
            "UPDATE flist SET body = ?1 WHERE realpath = ?2",
            rusqlite::params![&encrypted_content, &realpath],
        )?;

        println!("File '{}' successfully updated in vault", filename);
        Ok(())
    }

    fn remove(filename: &str) -> Result<(), DmError> {
        let conn = Self::open_database()?;
        let realpath = Self::get_absolute_path(filename)?;

        let rows_affected = conn.execute(
            "DELETE FROM flist WHERE realpath = ?1",
            rusqlite::params![&realpath],
        )?;

        if rows_affected == 0 {
            println!("File '{}' not found in vault", filename);
        } else {
            println!("File '{}' successfully removed from vault", filename);
        }

        Ok(())
    }

    fn export(filename: &str, rel: bool, confirm: bool) -> Result<(), DmError> {
        let conn = Self::open_database()?;
        let realpath = Self::get_absolute_path(filename)?;

        // Get the encrypted content from the vault
        let encrypted_content: Vec<u8> = conn
            .query_row(
                "SELECT body FROM flist WHERE realpath = ?1",
                rusqlite::params![&realpath],
                |row| row.get(0),
            )
            .map_err(|_| DmError::FileNotInStorage(realpath))?;

        // Decrypt the content
        let decrypted_content = Self::decrypt_content(&encrypted_content)?;

        // Get file name for saving
        let mut output_filename = Path::new(filename).to_string_lossy();
        if rel {
            output_filename = Path::new(filename).file_name().unwrap().to_string_lossy();
        }

        if !confirm {
            // Check if file exists
            if Path::new(&*output_filename).exists() {
                print!(
                    "File '{}' already exists. Overwrite? (y/N): ",
                    output_filename
                );
                io::stdout().flush()?;
                let mut input = String::new();
                io::stdin().read_line(&mut input)?;
                if !input.trim().to_lowercase().starts_with('y') {
                    println!("Export canceled");
                    return Ok(());
                }
            }
        }

        // Save decrypted content
        fs::write(&*output_filename, decrypted_content)?;

        println!("File '{}' exported", output_filename);
        Ok(())
    }

    fn open_database() -> Result<Connection, DmError> {
        if !Path::new(DB_NAME).exists() {
            return Err(DmError::DatabaseNotFound);
        }
        Ok(Connection::open(DB_NAME)?)
    }

    fn get_absolute_path(filename: &str) -> Result<String, DmError> {
        let path = Path::new(filename);
        let absolute_path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };

        Ok(absolute_path.to_string_lossy().to_string())
    }

    fn verify_gpg_key(key_hash: &str) -> Result<(), DmError> {
        let mut ctx = Context::from_protocol(Protocol::OpenPgp)?;

        // Get the key by hash
        match ctx.get_key(key_hash) {
            Ok(key) => {
                // Check if the key can be used for encryption
                if key.can_encrypt() {
                    println!("GPG key found and can be used for encryption");
                    Ok(())
                } else {
                    eprintln!("Key cannot be used for encryption");
                    eprintln!(
                        "Please ensure the key is not expired and has encryption capabilities"
                    );
                    Err(DmError::GpgKeyNotFound(format!(
                        "{} (key cannot be used for encryption)",
                        key_hash
                    )))
                }
            }
            Err(e) => {
                eprintln!("GPG key not found: {}", e);
                eprintln!("Try run: gpg --list-keys {}", key_hash);
                Err(DmError::GpgKeyNotFound(key_hash.to_string()))
            }
        }
    }

    fn get_gpg_key_hash(conn: &Connection) -> Result<String, DmError> {
        let key_hash: String = conn.query_row(
            "SELECT value FROM config WHERE key = ?1",
            rusqlite::params![GPG_KEY_HASH_CONFIG],
            |row| row.get(0),
        )?;
        Ok(key_hash)
    }

    fn encrypt_content(content: &[u8], key_hash: &str) -> Result<Vec<u8>, DmError> {
        let mut ctx = Context::from_protocol(Protocol::OpenPgp)?;

        // Set armor mode for better compatibility
        ctx.set_armor(true);

        // Get key
        let key = ctx.get_key(key_hash)?;

        // Check if key can encrypt
        if !key.can_encrypt() {
            return Err(DmError::GpgError(gpgme::Error::from_code(110))); // Generic unusable key error
        }

        // Set trust mode (trust all keys)
        ctx.set_offline(true);

        let mut output = Vec::new();

        // Encrypt with more detailed error handling
        match ctx.encrypt(Some(&key), content, &mut output) {
            Ok(_) => {
                // println!(
                //     "File encrypted successfully ({} bytes -> {} bytes)",
                //     content.len(),
                //     output.len()
                // );
                Ok(output)
            }
            Err(e) => {
                eprintln!("Encrypt error: {}", e);
                eprintln!("Error code: {}", e.code());

                // Additional diagnostics
                if e.code() == 110 {
                    // Using a generic error code for unusable pubkey
                    eprintln!("GPG key cannot be used for encryption.");
                    eprintln!("Possible reasons:");
                    eprintln!("1. Key expired");
                    eprintln!("2. Key revoked");
                    eprintln!("3. Key has no encryption subkey");
                    eprintln!("4. Insufficient trust level for key");
                    eprintln!("");
                    eprintln!("Try running:");
                    eprintln!("  gpg --edit-key {} trust", key_hash);
                    eprintln!("  (then select '5' for absolute trust)");
                }

                Err(DmError::GpgError(e))
            }
        }
    }

    fn decrypt_content(encrypted_content: &[u8]) -> Result<Vec<u8>, DmError> {
        let mut ctx = Context::from_protocol(Protocol::OpenPgp)?;

        let mut output = Vec::new();

        match ctx.decrypt(encrypted_content, &mut output) {
            Ok(_) => {
                // println!(
                //     "File successfully decrypted ({} bytes -> {} bytes)",
                //     encrypted_content.len(),
                //     output.len()
                // );
                Ok(output)
            }
            Err(e) => {
                eprintln!("Decrypt error: {}", e);
                eprintln!("Error code: {}", e.code());

                if e.code() == 9 {
                    // Generic "no secret key" error code
                    eprintln!("GPG key not found");
                    eprintln!("Make sure you have the corresponding private key");
                } else if e.code() == 11 {
                    // Generic "bad passphrase" error code
                    eprintln!("Invalid passphrase for private key");
                    eprintln!("Make sure gpg-agent is running and configured");
                }

                Err(DmError::GpgError(e))
            }
        }
    }

    fn diagnose_key(key_hash: &str) -> Result<(), DmError> {
        let mut ctx = Context::from_protocol(Protocol::OpenPgp)?;

        match ctx.get_key(key_hash) {
            Ok(key) => {
                println!("✅ GPG key found in keyring");

                // Check key capabilities
                println!("\nKey capabilities:");
                println!(
                    "  - Encryption: {}",
                    if key.can_encrypt() {
                        "✅ Yes"
                    } else {
                        "❌ No"
                    }
                );
                println!(
                    "  - Signing: {}",
                    if key.can_sign() { "✅ Yes" } else { "❌ No" }
                );
                println!(
                    "  - Certification: {}",
                    if key.can_certify() {
                        "✅ Yes"
                    } else {
                        "❌ No"
                    }
                );
                println!(
                    "  - Authentication: {}",
                    if key.can_authenticate() {
                        "✅ Yes"
                    } else {
                        "❌ No"
                    }
                );

                // Display key details
                println!("\nDetails:");
                println!("  - ID: {}", key.id().unwrap_or("Unknown"));
                println!(
                    "  - Fingerprint: {}",
                    key.fingerprint().unwrap_or("Unknown")
                );

                // Collect subkeys - direct collection without Result handling
                let subkeys: Vec<_> = key.subkeys().collect();

                println!("Subkeys ({}):", subkeys.len());
                for (i, subkey) in subkeys.iter().enumerate() {
                    println!("  Subkey #{}", i + 1);
                    println!("    - ID: {}", subkey.id().unwrap_or("Unknown"));
                    println!(
                        "    - Can encrypt: {}",
                        if subkey.can_encrypt() {
                            "✅ Yes"
                        } else {
                            "❌ No"
                        }
                    );
                }

                // Collect user IDs - direct collection without Result handling
                let uids: Vec<_> = key.user_ids().collect();

                println!("\nUser IDs ({}):", uids.len());
                for (i, uid) in uids.iter().enumerate() {
                    println!("  ID #{}", i + 1);
                    println!("    - Name: {}", uid.name().unwrap_or("Unknown"));
                    println!("    - Email: {}", uid.email().unwrap_or("Unknown"));
                }

                // Test encryption capability with a small message
                if key.can_encrypt() {
                    println!("\nEncryption testing:");
                    let test_data = b"Test encryption capability";
                    match Self::encrypt_content(test_data, key_hash) {
                        Ok(_) => println!("  ✅ Encryption successful"),
                        Err(e) => println!("  ❌ Encryption failed: {}", e),
                    }
                } else {
                    println!("\nEncryption testing: ❌ Skipped (key does not support encryption)");
                }

                // Additional diagnostics and recommendations
                if !key.can_encrypt() {
                    println!("\n❌ Problem: Key cannot be used for encryption");
                    println!("   Solution: Create a new key with encryption capability or add a subkey for encryption");
                } else {
                    println!("\n✅ Key is suitable for use with dark-matter");
                }

                Ok(())
            }
            Err(e) => {
                println!("❌ GPG key not found: {}", e);
                println!("\nDiagnosis:");
                println!("1. Check the hash: {}", key_hash);
                println!("2. Check available keys:");
                println!("   $ gpg --list-keys");
                println!("3. Maybe you need to import the key:");
                println!("   $ gpg --import path/to/key.asc");

                Err(DmError::GpgKeyNotFound(key_hash.to_string()))
            }
        }
    }
}

fn handle_secrets_command(action: SecretsCommands) -> Result<(), DmError> {
    match action {
        SecretsCommands::Add { name, value, tags } => {
            // Here you would implement the logic to add a secret
            //println!("Adding secret '{}' with tags '{}'", name, tags);
            DataManager::add_secret(&name, &value, &tags).map_err(|e| {
                eprintln!("Error adding secret: {}", e);
                e
            })?;
            Ok(())
        }
        SecretsCommands::List { tags } => {
            // Here you would implement the logic to list secrets
            //println!("Listing all secrets");
            DataManager::list_secrets(&tags).map_err(|e| {
                eprintln!("Error listing secrets: {}", e);
                e
            })?;
            Ok(())
        }
        SecretsCommands::Update { name, value, tags } => {
            // Here you would implement the logic to update a secret
            //println!("Updating secret '{}' with tags '{}'", name, tags);
            DataManager::update_secret(&name, &value, &tags).map_err(|e| {
                eprintln!("Error updating secret: {}", e);
                e
            })?;
            Ok(())
        }
        SecretsCommands::Remove { name } => {
            // Here you would implement the logic to remove a secret
            //println!("Removing secret '{}'", name);
            DataManager::remove_secret(&name).map_err(|e| {
                eprintln!("Error removing secret: {}", e);
                e
            })?;
            Ok(())
        }
        SecretsCommands::Show { name } => {
            // Here you would implement the logic to show a secret
            //println!("Showing secret '{}'", name);
            DataManager::show_secret(&name).map_err(|e| {
                eprintln!("Error showing secret: {}", e);
                e
            })?;
            Ok(())
        }
    }
}

fn handle_key_command(action: KeysCommands) -> Result<(), DmError> {
    match action {
        KeysCommands::Validate { key_hash } => DataManager::diagnose_key(&key_hash),
    }
}

fn handle_file_command(action: FileCommands) -> Result<(), DmError> {
    match action {
        FileCommands::Add { filename } => DataManager::add(&filename),
        FileCommands::List => DataManager::list(),
        FileCommands::Update { filename } => DataManager::update(&filename),
        FileCommands::Remove { filename } => DataManager::remove(&filename),
        FileCommands::Export {
            filename,
            relative,
            confirm,
        } => DataManager::export(&filename, relative, confirm),
    }
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Init { key_hash } => DataManager::init(&key_hash),
        Commands::File { action } => handle_file_command(action),
        Commands::Keys { action } => handle_key_command(action),
        Commands::Secret { action } => handle_secrets_command(action),
    };
    if let Err(error) = result {
        eprintln!("{}", error);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use tempfile::TempDir;

    #[test]
    fn test_get_absolute_path() {
        let temp_dir = TempDir::new().unwrap();
        env::set_current_dir(&temp_dir).unwrap();

        let relative_path = "test.txt";
        let absolute_path = DataManager::get_absolute_path(relative_path).unwrap();

        assert!(absolute_path.contains("test.txt"));
        assert!(Path::new(&absolute_path).is_absolute());
    }
}
