use clap::{Parser, Subcommand};
use gpgme::{Context, Protocol};
use rusqlite::Connection;
use std::fs;
use std::io::{self, Write};
use std::path::Path;

const DB_NAME: &str = "dm.db";
const GPG_KEY_HASH_CONFIG: &str = "gpg_key_hash";

#[derive(Parser)]
#[command(name = "dark-matter")]
#[command(about = "dark matter - CLI утилита для безопасного управления файлами с GPG шифрованием")]
#[command(version = "1.0.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Инициализирует новое хранилище в текущем каталоге
    Init {
        /// Хеш GPG ключа для шифрования
        key_hash: String,
    },
    /// Добавляет новый файл в хранилище
    Add {
        /// Путь к файлу для добавления
        filename: String,
    },
    /// Отображает список всех файлов в хранилище
    List,
    /// Обновляет содержимое существующего файла в хранилище
    Update {
        /// Путь к файлу для обновления
        filename: String,
    },
    /// Удаляет файл из хранилища
    Remove {
        /// Путь к файлу для удаления
        filename: String,
    },
    /// Экспортирует и расшифровывает файл из хранилища
    Export {
        /// Путь к файлу для экспорта
        filename: String,
    },
    /// Диагностика GPG ключа
    Diagnose {
        /// Хеш GPG ключа для диагностики
        key_hash: String,
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
    DatabaseError(rusqlite::Error),
    GpgError(gpgme::Error),
    IoError(io::Error),
}

impl std::fmt::Display for DmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DmError::DatabaseNotFound => {
                write!(f, "Ошибка: База данных dm.db не найдена в текущем каталоге")
            }
            DmError::DatabaseAlreadyExists => write!(f, "Ошибка: База данных dm.db уже существует"),
            DmError::FileNotFound(path) => write!(f, "Ошибка: Файл '{}' не найден", path),
            DmError::GpgKeyNotFound(hash) => {
                write!(f, "Ошибка: GPG ключ с хешем '{}' не найден", hash)
            }
            DmError::FileAlreadyExists(path) => write!(
                f,
                "Ошибка: Файл '{}' уже существует в хранилище. Используйте команду update",
                path
            ),
            DmError::FileNotInStorage(path) => {
                write!(f, "Ошибка: Файл '{}' не найден в хранилище", path)
            }
            DmError::DatabaseError(e) => write!(f, "Ошибка базы данных: {}", e),
            DmError::GpgError(e) => write!(f, "Ошибка GPG: {}", e),
            DmError::IoError(e) => write!(f, "Ошибка ввода/вывода: {}", e),
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
        // Проверяем, что база данных еще не существует
        if Path::new(DB_NAME).exists() {
            return Err(DmError::DatabaseAlreadyExists);
        }

        // Проверяем наличие GPG ключа
        Self::verify_gpg_key(key_hash)?;

        // Создаем базу данных и таблицы
        let conn = Connection::open(DB_NAME)?;

        conn.execute(
            "CREATE TABLE config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
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

        // Сохраняем хеш ключа в конфигурации
        conn.execute(
            "INSERT INTO config (key, value) VALUES (?1, ?2)",
            rusqlite::params![GPG_KEY_HASH_CONFIG, key_hash],
        )?;

        println!(
            "Хранилище успешно инициализировано с GPG ключом: {}",
            key_hash
        );
        Ok(())
    }

    fn add(filename: &str) -> Result<(), DmError> {
        let conn = Self::open_database()?;
        let realpath = Self::get_absolute_path(filename)?;

        // Проверяем существование файла
        if !Path::new(filename).exists() {
            return Err(DmError::FileNotFound(filename.to_string()));
        }

        // Проверяем, что файл еще не добавлен
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM flist WHERE realpath = ?1",
            rusqlite::params![&realpath],
            |row| row.get(0),
        )?;

        if count > 0 {
            return Err(DmError::FileAlreadyExists(realpath));
        }

        // Читаем содержимое файла
        let content = fs::read(filename)?;

        // Получаем GPG ключ из конфигурации
        let key_hash = Self::get_gpg_key_hash(&conn)?;

        // Шифруем содержимое
        let encrypted_content = Self::encrypt_content(&content, &key_hash)?;

        // Сохраняем в базу данных
        conn.execute(
            "INSERT INTO flist (realpath, body) VALUES (?1, ?2)",
            rusqlite::params![&realpath, &encrypted_content],
        )?;

        println!("Файл '{}' успешно добавлен в хранилище", filename);
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
            println!("Хранилище пусто");
        } else {
            println!("Файлы в хранилище:");
            for file in files {
                println!("  {}", file);
            }
        }

        Ok(())
    }

    fn update(filename: &str) -> Result<(), DmError> {
        let conn = Self::open_database()?;
        let realpath = Self::get_absolute_path(filename)?;

        // Проверяем существование файла на диске
        if !Path::new(filename).exists() {
            return Err(DmError::FileNotFound(filename.to_string()));
        }

        // Проверяем, что файл есть в хранилище
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM flist WHERE realpath = ?1",
            rusqlite::params![&realpath],
            |row| row.get(0),
        )?;

        if count == 0 {
            return Err(DmError::FileNotInStorage(realpath));
        }

        // Читаем новое содержимое файла
        let content = fs::read(filename)?;

        // Получаем GPG ключ из конфигурации
        let key_hash = Self::get_gpg_key_hash(&conn)?;

        // Шифруем содержимое
        let encrypted_content = Self::encrypt_content(&content, &key_hash)?;

        // Обновляем запись в базе данных
        conn.execute(
            "UPDATE flist SET body = ?1 WHERE realpath = ?2",
            rusqlite::params![&encrypted_content, &realpath],
        )?;

        println!("Файл '{}' успешно обновлен в хранилище", filename);
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
            println!("Файл '{}' не найден в хранилище", filename);
        } else {
            println!("Файл '{}' успешно удален из хранилища", filename);
        }

        Ok(())
    }

    fn export(filename: &str) -> Result<(), DmError> {
        let conn = Self::open_database()?;
        let realpath = Self::get_absolute_path(filename)?;

        // Получаем зашифрованное содержимое из базы данных
        let encrypted_content: Vec<u8> = conn
            .query_row(
                "SELECT body FROM flist WHERE realpath = ?1",
                rusqlite::params![&realpath],
                |row| row.get(0),
            )
            .map_err(|_| DmError::FileNotInStorage(realpath))?;

        // Расшифровываем содержимое
        let decrypted_content = Self::decrypt_content(&encrypted_content)?;

        // Определяем имя файла для сохранения
        let output_filename = Path::new(filename).file_name().unwrap().to_string_lossy();

        // Проверяем, существует ли файл с таким именем
        if Path::new(&*output_filename).exists() {
            print!(
                "Файл '{}' уже существует. Перезаписать? (y/N): ",
                output_filename
            );
            io::stdout().flush()?;

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;

            if !input.trim().to_lowercase().starts_with('y') {
                println!("Экспорт отменен");
                return Ok(());
            }
        }

        // Сохраняем расшифрованное содержимое
        fs::write(&*output_filename, decrypted_content)?;

        println!("Файл успешно экспортирован как '{}'", output_filename);
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

        // Пытаемся найти ключ по хешу
        match ctx.get_key(key_hash) {
            Ok(key) => {
                // Проверяем, что ключ можно использовать для шифрования
                if key.can_encrypt() {
                    println!("GPG ключ найден и может использоваться для шифрования");
                    Ok(())
                } else {
                    eprintln!("Найденный ключ не может использоваться для шифрования");
                    eprintln!("Убедитесь, что ключ не истек и имеет возможность шифрования");
                    Err(DmError::GpgKeyNotFound(format!(
                        "{} (ключ не подходит для шифрования)",
                        key_hash
                    )))
                }
            }
            Err(e) => {
                eprintln!("Не удалось найти GPG ключ: {}", e);
                eprintln!("Попробуйте выполнить: gpg --list-keys {}", key_hash);
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

        // Устанавливаем режим ASCII armor для лучшей совместимости
        ctx.set_armor(true);

        // Получаем ключ
        let key = ctx.get_key(key_hash)?;

        // Проверяем, что ключ можно использовать для шифрования
        if !key.can_encrypt() {
            return Err(DmError::GpgError(gpgme::Error::from_code(110))); // Generic unusable key error
        }

        // Устанавливаем режим доверия (trust all keys)
        ctx.set_offline(true);

        let mut output = Vec::new();

        // Шифруем с более подробной обработкой ошибок
        match ctx.encrypt(Some(&key), content, &mut output) {
            Ok(_) => {
                println!(
                    "Файл успешно зашифрован ({} байт -> {} байт)",
                    content.len(),
                    output.len()
                );
                Ok(output)
            }
            Err(e) => {
                eprintln!("Ошибка шифрования: {}", e);
                eprintln!("Код ошибки: {}", e.code());

                // Дополнительная диагностика
                if e.code() == 110 {
                    // Using a generic error code for unusable pubkey
                    eprintln!("Ключ не может быть использован для шифрования.");
                    eprintln!("Возможные причины:");
                    eprintln!("1. Ключ истек");
                    eprintln!("2. Ключ отозван");
                    eprintln!("3. Ключ не имеет подключа для шифрования");
                    eprintln!("4. Недостаточный уровень доверия к ключу");
                    eprintln!("");
                    eprintln!("Попробуйте выполнить:");
                    eprintln!("  gpg --edit-key {} trust", key_hash);
                    eprintln!("  (затем выберите '5' для абсолютного доверия)");
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
                println!(
                    "Файл успешно расшифрован ({} байт -> {} байт)",
                    encrypted_content.len(),
                    output.len()
                );
                Ok(output)
            }
            Err(e) => {
                eprintln!("Ошибка расшифровки: {}", e);
                eprintln!("Код ошибки: {}", e.code());

                if e.code() == 9 {
                    // Generic "no secret key" error code
                    eprintln!("Не найден приватный ключ для расшифровки");
                    eprintln!("Убедитесь, что у вас есть соответствующий приватный ключ");
                } else if e.code() == 11 {
                    // Generic "bad passphrase" error code
                    eprintln!("Неверный пароль для приватного ключа");
                    eprintln!("Убедитесь, что gpg-agent запущен и настроен");
                }

                Err(DmError::GpgError(e))
            }
        }
    }

    fn diagnose_key(key_hash: &str) -> Result<(), DmError> {
        let mut ctx = Context::from_protocol(Protocol::OpenPgp)?;

        match ctx.get_key(key_hash) {
            Ok(key) => {
                println!("✅ GPG ключ найден в keyring");

                // Check key capabilities
                println!("\nВозможности ключа:");
                println!(
                    "  - Шифрование: {}",
                    if key.can_encrypt() {
                        "✅ Да"
                    } else {
                        "❌ Нет"
                    }
                );
                println!(
                    "  - Подпись: {}",
                    if key.can_sign() {
                        "✅ Да"
                    } else {
                        "❌ Нет"
                    }
                );
                println!(
                    "  - Сертификация: {}",
                    if key.can_certify() {
                        "✅ Да"
                    } else {
                        "❌ Нет"
                    }
                );
                println!(
                    "  - Аутентификация: {}",
                    if key.can_authenticate() {
                        "✅ Да"
                    } else {
                        "❌ Нет"
                    }
                );

                // Display key details
                println!("\nДетали ключа:");
                println!("  - ID: {}", key.id().unwrap_or("Неизвестно"));
                println!(
                    "  - Отпечаток: {}",
                    key.fingerprint().unwrap_or("Неизвестно")
                );

                // Collect subkeys - direct collection without Result handling
                let subkeys: Vec<_> = key.subkeys().collect();

                println!("\nПодключи ({}):", subkeys.len());
                for (i, subkey) in subkeys.iter().enumerate() {
                    println!("  Подключ #{}", i + 1);
                    println!("    - ID: {}", subkey.id().unwrap_or("Неизвестно"));
                    println!(
                        "    - Может шифровать: {}",
                        if subkey.can_encrypt() {
                            "✅ Да"
                        } else {
                            "❌ Нет"
                        }
                    );
                }

                // Collect user IDs - direct collection without Result handling
                let uids: Vec<_> = key.user_ids().collect();

                println!("\nИдентификаторы пользователей ({}):", uids.len());
                for (i, uid) in uids.iter().enumerate() {
                    println!("  Идентификатор #{}", i + 1);
                    println!("    - Имя: {}", uid.name().unwrap_or("Неизвестно"));
                    println!("    - Email: {}", uid.email().unwrap_or("Неизвестно"));
                }

                // Test encryption capability with a small message
                if key.can_encrypt() {
                    println!("\nТестирование шифрования:");
                    let test_data = b"Test encryption capability";
                    match Self::encrypt_content(test_data, key_hash) {
                        Ok(_) => println!("  ✅ Шифрование успешно"),
                        Err(e) => println!("  ❌ Шифрование не удалось: {}", e),
                    }
                } else {
                    println!(
                        "\nТестирование шифрования: ❌ Пропущено (ключ не поддерживает шифрование)"
                    );
                }

                // Additional diagnostics and recommendations
                if !key.can_encrypt() {
                    println!("\n❌ Проблема: Ключ не может использоваться для шифрования");
                    println!("   Решение: Создайте новый ключ с возможностью шифрования или добавьте подключ для шифрования");
                } else {
                    println!("\n✅ Ключ подходит для использования с dm");
                }

                Ok(())
            }
            Err(e) => {
                println!("❌ GPG ключ не найден: {}", e);
                println!("\nДиагностика:");
                println!("1. Проверьте правильность хеша: {}", key_hash);
                println!("2. Проверьте доступные ключи:");
                println!("   $ gpg --list-keys");
                println!("3. Возможно, нужно импортировать ключ:");
                println!("   $ gpg --import path/to/key.asc");

                Err(DmError::GpgKeyNotFound(key_hash.to_string()))
            }
        }
    }
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Init { key_hash } => DataManager::init(&key_hash),
        Commands::Add { filename } => DataManager::add(&filename),
        Commands::List => DataManager::list(),
        Commands::Update { filename } => DataManager::update(&filename),
        Commands::Remove { filename } => DataManager::remove(&filename),
        Commands::Export { filename } => DataManager::export(&filename),
        Commands::Diagnose { key_hash } => DataManager::diagnose_key(&key_hash),
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
