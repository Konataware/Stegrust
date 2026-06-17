// Copyright (C) 2026 João Henrique, João Pedro, João Venturini, Luãn Fernandes
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use rusqlite_migration::{Migrations, M};
use std::fs;
use std::path::PathBuf;

use crate::crypto::{derive_key, gen_salt};
use crate::keyring;

const DB_SALT_FILE: &str = "db_salt.bin";
const CONFIG_DIR: &str = ".config/stegrust";

fn get_config_dir() -> PathBuf {
    let home = std::env::var("HOME").expect("HOME não definido");
    PathBuf::from(home).join(CONFIG_DIR)
}

fn get_db_salt() -> Result<[u8; 16]> {
    let config_dir = get_config_dir();
    if !config_dir.exists() {
        fs::create_dir_all(&config_dir)
            .context("Failed to create a config directory")?;
    }

    let salt_path = config_dir.join(DB_SALT_FILE);
    if salt_path.exists() {
        let salt_bytes = fs::read(&salt_path)
            .context("Failed to read salt file")?;
        if salt_bytes.len() == 16 {
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&salt_bytes);
            Ok(salt)
        } else {
            Err(anyhow::anyhow!("Salt file appears to be corrupted"))
        }
    } else {
        let salt = gen_salt();
        fs::write(&salt_path, &salt)
            .context("Failed to save salt file")?;
        Ok(salt)
    }
}

fn get_db_key() -> Result<String> {
    let password = keyring::get_master_password()?;
    let salt = get_db_salt()?;
    let key_bytes = derive_key(&password, &salt)
        .map_err(|e| anyhow::anyhow!("Failed at key derivation: {}", e))?;
    Ok(hex::encode(key_bytes))
}

fn apply_migrations(conn: &mut Connection, key: &str) -> Result<()> {
    conn.pragma_update(None, "key", key)
        .context("Failed at applying the key to SQLCipher")?;
    
    let migrations = Migrations::new(vec![
        M::up(
            "CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                filename TEXT
            )"
        ),
    ]);
    
    migrations.to_latest(conn)
        .map_err(|e| {
            // error detection to send out a friendlier wrong password error
            let err_msg = e.to_string();
            if err_msg.contains("file is not a database") 
                || err_msg.contains("hmac check failed")
                || err_msg.contains("decrypting page") {
                anyhow::anyhow!("Wrong password for the database. Try again.")
            } else {
                anyhow::anyhow!("Failed to execute migrations: {}", e)
            }
        })?;
    Ok(())
}

pub fn open_db() -> Result<Connection> {
    let config_dir = get_config_dir();
    if !config_dir.exists() {
        fs::create_dir_all(&config_dir)
            .context("Failed to create config file")?;
    }
    
    let db_path = config_dir.join("entries.db");
    
    let mut conn = Connection::open(&db_path)
        .map_err(|e| {
            if e.to_string().contains("file is not a database") {
                anyhow::anyhow!("Wrong password for the database. Try again")
            } else {
                anyhow::anyhow!("Failed to open the database: {}", e)
            }
        })?;
    
    let key = get_db_key()?;
    apply_migrations(&mut conn, &key)?;
    
    Ok(conn)
}

pub fn add_entry(name: &str, filename: &str) -> Result<i64> {
    let conn = open_db()?;
    conn.execute(
        "INSERT INTO entries (name, filename) VALUES (?1, ?2)",
        params![name, filename],
    ).context("Failed to add entry")?;
    let id = conn.last_insert_rowid();
    Ok(id)
}

pub fn remove_entry(id: i64) -> Result<bool> {
    let conn = open_db()?;
    let rows_affected = conn.execute(
        "DELETE FROM entries WHERE id = ?1",
        params![id],
    ).context("Failed to remove entry")?;
    Ok(rows_affected > 0)
}

pub fn list_entries() -> Result<Vec<(i64, String, Option<String>)>> {
    let conn = open_db()?;
    let mut stmt = conn.prepare("SELECT id, name, filename FROM entries ORDER BY name")
        .context("Failed to prepare query")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?))
    }).context("Failed to list entries.")?;
    
    let mut entries = Vec::new();
    for row in rows {
        entries.push(row?);
    }
    Ok(entries)
}

pub fn update_entry(id: i64, name: Option<&str>, filename: Option<&str>) -> Result<bool> {
    let conn = open_db()?;
    
    let mut updates = Vec::new();
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    
    if let Some(n) = name {
        updates.push("name = ?");
        params.push(Box::new(n));
    }
    if let Some(f) = filename {
        updates.push("filename = ?");
        params.push(Box::new(f));
    }
    
    if updates.is_empty() {
        return Err(anyhow::anyhow!("No fields sent for updating"));
    }
    
    let query = format!(
        "UPDATE entries SET {} WHERE id = ?",
        updates.join(", ")
    );
    params.push(Box::new(id));
    
    let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter()
        .map(|p| p.as_ref())
        .collect();
    
    let rows_affected = conn.execute(&query, &param_refs[..])
        .context("Failed to update entry")?;
    
    Ok(rows_affected > 0)
}