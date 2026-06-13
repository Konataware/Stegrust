use anyhow::Ok;
use clap::{ Parser };
use rpassword::read_password;
use hex;
use crate::crypto::{ gen_salt, derive_key, encrypt, decrypt_full };

pub mod crypto;
pub mod cli;

use crate::cli::{Cli, Commands};


fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encode { data } => {
            eprintln!("Type in your password: ");
            let password = read_password()?;

            let salt = gen_salt();
            let key = derive_key(&password, &salt)
                .map_err(|e| anyhow::anyhow!("Key derivation failed: {}", e))?;

            let encrypted_payload = encrypt(data.as_bytes(), &key)
                .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

            let mut full_payload = salt.to_vec();
            full_payload.extend_from_slice(&encrypted_payload);

            println!("Payload (hex): {}", hex::encode(&full_payload));
            println!("Salt (hex): {}", hex::encode(&salt));
            println!("Nonce + Ciphertext + Tag (hex): {}", hex::encode(&encrypted_payload));
            println!("Total size: {} bytes", full_payload.len());
            
        }

        Commands::Decode { payload } => {
            let payload_bytes = hex::decode(&payload)
                .map_err(|e| anyhow::anyhow!("Error when decoding hex: {}", e))?;

            eprintln!("Type in your password: ");
            let password = read_password()?;

            let plaintext = decrypt_full(&payload_bytes, &password)?;

            let decrypted_str = String::from_utf8(plaintext)
                .map_err(|e| anyhow::anyhow!("Deciphered data is not UTF-8 valid: {}", e))?;
            println!("Deciphered message: {}", decrypted_str);
        },
        Commands::List => todo!(),
        #[allow(unused)]
        Commands::Add { name, filename } => todo!(),
        #[allow(unused)]
        Commands::Update { id, name, filename } => todo!(),
        #[allow(unused)]
        Commands::Delete { id } => todo!(),
        
    }
    Ok(())
}
