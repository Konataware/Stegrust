use anyhow::Ok;
use clap::{ Parser };
use rpassword::read_password;
use std::path::{PathBuf};

use crate::crypto::{ gen_salt, derive_key, encrypt, decrypt_full };
use crate::cli::{Cli, Commands};
use crate::stego_bridge::{ stego_encode, stego_decode };

pub mod crypto;
pub mod cli;
pub mod stego_bridge;



fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encode { input, output, data } => {
            eprint!("Master key: ");
            let password = read_password()?;

            let salt = gen_salt();
            let key = derive_key(&password, &salt)
                .map_err(|e| anyhow::anyhow!("[ERROR] Key derivation failed: {}", e))?;

            let encrypted_payload = encrypt(data.as_bytes(), &key)
                .map_err(|e| anyhow::anyhow!("[ERROR] Encryption failed: {}", e))?;

            let mut full_payload = salt.to_vec();
            full_payload.extend_from_slice(&encrypted_payload);

            stego_encode(&PathBuf::from(&input), &PathBuf::from(&output), &full_payload)?;
            println!("Data successfully hidden in {}", output);
        }

        Commands::Decode { input } => {
            eprint!("Insert your key: ");
            let password = read_password()?;

            let payload = stego_decode(&PathBuf::from(&input))?;

            let plaintext = decrypt_full(&payload, &password)?;
            let decrypted_str = String::from_utf8(plaintext)
                .map_err(|e| anyhow::anyhow!("[ERROR] Decrypted data is not in valid UTF-8: {}", e))?;
            println!("{}", decrypted_str);
        },
        Commands::List => todo!(),
        Commands::Add { name: _, filename: _ } => todo!(),
        Commands::Update { id: _, name: _, filename: _ } => todo!(),
        Commands::Delete { id: _ } => todo!(),
    }
    Ok(())
}
