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

mod cli;
mod crypto;
mod stego_bridge;
mod db;
mod keyring;

use anyhow::Ok;
use clap::{CommandFactory, Parser};
use std::path::PathBuf;

use crate::cli::Cli;
use crate::crypto::{gen_salt, derive_key, encrypt, decrypt_full};
use crate::stego_bridge::{stego_encode, stego_decode};
use crate::db::conn::{remove_entry, list_entries, add_entry, update_entry};
use crate::keyring::get_master_password;

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match () {
        _ if cli.add => {
            let name = cli.name.as_deref().ok_or_else(|| anyhow::anyhow!("--name is required for --add"))?;
            let filename = cli.filename.as_deref().ok_or_else(|| anyhow::anyhow!("--filename is required for --add"))?;
            let id = add_entry(name, filename)?;
            println!("Entry added with ID: {}", id);
        }

        _ if cli.encode => {
            let input = cli.input.as_deref().ok_or_else(|| anyhow::anyhow!("--input is required for --encode"))?;
            let output = cli.output.as_deref().ok_or_else(|| anyhow::anyhow!("--output is required for --encode"))?;
            let data = cli.data.as_deref().ok_or_else(|| anyhow::anyhow!("--data is required for --encode"))?;

            let password = get_master_password()?;
            let salt = gen_salt();
            let key = derive_key(&password, &salt)
                .map_err(|e| anyhow::anyhow!("Key derivation failed: {}", e))?;
            let encrypted_payload = encrypt(data.as_bytes(), &key)
                .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
            let mut full_payload = salt.to_vec();
            full_payload.extend_from_slice(&encrypted_payload);

            stego_encode(&PathBuf::from(input), &PathBuf::from(output), &full_payload)?;
            println!("Data successfully hidden in {}", output);
        }

        _ if cli.decode => {
            let input = cli.input.as_deref().ok_or_else(|| anyhow::anyhow!("--input is required for --decode"))?;

            let password = get_master_password()?;
            let payload = stego_decode(&PathBuf::from(input))?;
            let plaintext = decrypt_full(&payload, &password)?;
            let decrypted_str = String::from_utf8(plaintext)
                .map_err(|e| anyhow::anyhow!("Decrypted data is not valid UTF-8: {}", e))?;
            println!("{}", decrypted_str);
        }

        _ if cli.list => {
            let entries = list_entries()?;
            if entries.is_empty() {
                println!("No entries found.");
            } else {
                for (id, name, filename) in entries {
                    let filename_display = filename.unwrap_or_else(|| "(none)".to_string());
                    println!("ID: {} | Name: {} | File: {}", id, name, filename_display);
                }
            }
        }

        _ if cli.delete => {
            let id = cli.id.ok_or_else(|| anyhow::anyhow!("--id is required for --delete"))?;
            let removed = remove_entry(id)?;
            if removed {
                println!("Entry with ID {} removed successfully.", id);
            } else {
                println!("No entry found with ID {}.", id);
            }
        }

        _ if cli.update => {
            let id = cli.id.ok_or_else(|| anyhow::anyhow!("--id is required for --update"))?;
            let name = cli.name.as_deref();
            let filename = cli.filename.as_deref();
            let updated = update_entry(id, name, filename)?;
            if updated {
                println!("Entry with ID {} updated successfully.", id);
            } else {
                println!("No entry found with ID {}.", id);
            }
        }

        _ => {
            println!("{}", Cli::command().render_help());
        }
    }

    Ok(())
}