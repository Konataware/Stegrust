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

use aes_gcm::{
    aead::{ Aead, KeyInit },
    Aes256Gcm, Nonce, Key
};
use argon2::{ Argon2, Params };
use getrandom;
use zeroize::Zeroize;
use anyhow::Result;


// gens a random 16 bytes salt
pub fn gen_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).unwrap();
    salt
}

// derive a 32 bytes key from the password and salt using Argon2id
// parameters: 64 MiB, 3 iterations, 1 lane and 32 output length
pub fn derive_key(password: &str, salt: &[u8; 16]) -> Result<[u8; 32], argon2::Error> {
    let params = Params::new(65536, 3, 1, Some(32)).expect("Valid argon2 parameters.");
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params
    );
    let mut output_key = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), salt, &mut output_key)?;
    Ok(output_key)
}

// cipher the plaintext using AES-256-GCM with the provided key
// this returns: nonce (12 bytes) + ciphertext (w/ auth tag)
pub fn encrypt(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, aes_gcm::Error> {

    // creates cipher using the key
    let key_struct = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key_struct);

    // gens a random 12 bytes nonce
    let nonce_bytes = gen_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);

    // finally, cipher! 
    let ciphertext = cipher.encrypt(nonce, plaintext)?;

    // concatenate nonce + ciphertext
    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

// gens a random 12 bytes nonce. 
pub fn gen_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce).unwrap();
    nonce
}

// deciphers a payload containing a nonce + ciphertext (w/ tag)
// returns the plaintext if the tag is valid
pub fn decrypt_with_key(encrypted_payload: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, aes_gcm::Error> {
    if encrypted_payload.len() < 12 {
        return Err(aes_gcm::Error);
    }
    let (nonce_bytes, ciphertext) = encrypted_payload.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let key_struct = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key_struct);
    cipher.decrypt(nonce, ciphertext)
}

// deciphers a complete payload containing salt + nonce + ciphertext (w/ tag)
// receives the password and extracts the initial salt
pub fn decrypt_full(payload: &[u8], password: &str) -> Result<Vec<u8>> {

    if payload.len() < 16 + 12 {
        return Err(anyhow::anyhow!("Payload is too short"));
    }
    let (salt_bytes, rest) = payload.split_at(16);
    let salt: [u8; 16] = salt_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("Failed to convert salt bytes to array"))?;

    let mut key = derive_key(password, &salt)
        .map_err(|e| anyhow::anyhow!("Argon2 KDF failed: {}", e))?;

    let plaintext = decrypt_with_key(rest, &key)
        .map_err(|e| anyhow::anyhow!("AES-GCM decryption failed: {:?}", e))?;

    // safe cleaning
    key.zeroize();

    Ok(plaintext)
}

// The above is testing code, probably should be removed later.
#[cfg(test)]
#[allow(unused)]
mod test_crypto {
    use super::*;
}

#[test]
fn test_encrypt_decrypt_with_key() {
    let key = [0x43; 32];
    let plaintext = b"terrifyingly great password that is undecipherable even against a gazillion attacks";
    let encrypted = encrypt(plaintext, &key).unwrap();
    let decrypted = decrypt_with_key(&encrypted, &key).unwrap();
    assert_eq!(&decrypted, plaintext);
}

#[test]
fn test_full_roundtrip() {
    let password = "terrifyingly great password and indistinguishable from the one in the other test";
    let original = b"image content";
    let salt = gen_salt();
    let key = derive_key(password, &salt).unwrap();
    let encrypted_part = encrypt(original, &key).unwrap();
    let mut payload = salt.to_vec();
    payload.extend_from_slice(&encrypted_part);
    let decrypted = decrypt_full(&payload, password).unwrap();
    assert_eq!(&decrypted, original);
}

#[test]
#[should_panic(expected = "AES-GCM decryption failed")]
fn test_wrong_password() {
    let password = "correct_one";
    let wrong = "wrong_one";

    let salt = gen_salt();
    let key = derive_key(password, &salt).unwrap();
    let plaintext = b"dados";
    let encrypted_part = encrypt(plaintext, &key).unwrap();
    let mut payload = salt.to_vec();
    payload.extend_from_slice(&encrypted_part);
    let _ = decrypt_full(&payload, wrong).unwrap();
}
