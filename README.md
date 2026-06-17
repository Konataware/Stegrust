# Stegrust

A command-line tool that combines strong cryptography with steganography to hide encrypted secrets inside PNG images.

## Overview

Stegrust allows you to store sensitive information (passwords, tokens, documents) inside ordinary images using Least Significant Bit (LSB) steganography. Before hiding, data is encrypted with AES-256-GCM using a key derived from your master password via Argon2id. The result is an image that looks identical to the original but contains a secret payload that can only be recovered with the correct master password.

### Key Features

- **Cryptography:** AES-256-GCM authenticated encryption with Argon2id key derivation
- **Steganography:** LSB embedding in PNG images (lossless format)
- **Index:** SQLCipher database to organize and manage multiple images
- **Keyring integration:** Master password stored securely in your system keyring
- **CLI:** Simple flag-based commands (`--encode`, `--decode`, `--list`, `--add`, `--update`, `--delete`)

---

## Installation

### From source

```bash
git clone https://github.com/Konataware/stegrust
cd stegrust
cargo build --release
sudo cp target/release/stegrust /usr/local/bin/
sudo cp -r python /usr/local/bin/
```

### Dependencies

- **Rust**
- **Python3** with the following packages:
  - `stegano`
  - `pillow`

Set up the Python environment:

```bash
cd /path/to/stegrust
python -m venv python/.venv
source python/.venv/bin/activate
pip install stegano pillow
```

The program expects the Python script at `python/stego.py` (relative to the binary or current directory).

---

## Quick Start

### 1. Add an entry to the index

```bash
stegrust --add --name "github" --filename "stego.png"
```

This registers a new entry in the SQLCipher database. The master password will be requested and stored in your system keyring.

### 2. Hide a secret in an image

```bash
stegrust --encode --input cover.png --output stego.png --data "github_token: ghp_123456"
```

The secret is encrypted and embedded into `stego.png`. The original `cover.png` remains unchanged.

### 3. Recover a secret

```bash
stegrust --decode --input stego.png
```

Extracts and decrypts the payload, printing the original secret.

### 4. List all indexed entries

```bash
stegrust --list
```

### 5. Update an entry

```bash
stegrust --update --id 1 --name "github-token"
```

### 6. Delete an entry (index only)

```bash
stegrust --delete --id 1
```

*Note: Deleting an entry does not remove the image file.*

---

## Command Reference

All commands use long flags. Short flags are available where indicated.

| Command | Flags | Description |
|---------|-------|-------------|
| `--encode` | `-i, --input`<br>`-o, --output`<br>`-m, --data` | Encrypt and hide data in an image |
| `--decode` | `-i, --input` | Extract and decrypt data from an image |
| `--list` | (none) | List all indexed entries |
| `--add` | `-n, --name`<br>`-f, --filename` | Add a new entry to the index |
| `--update` | `-d, --id`<br>`-n, --name` (optional)<br>`-f, --filename` (optional) | Update an existing entry |
| `--delete` | `-d, --id` | Remove an entry from the index |

---

## Security Architecture

### Master Password
- Stored in the system keyring (GNOME Keyring, KWallet, or Secret Service)
- Never written to disk
- Used to derive the AES-256-GCM encryption key

### Encryption Flow (Encode)
1. Generate a random **salt** (16 bytes) and **nonce** (12 bytes)
2. Derive a 256-bit key using **Argon2id** (64 MiB, 3 iterations)
3. Encrypt the payload with **AES-256-GCM** → ciphertext + authentication tag
4. Concatenate `salt + nonce + ciphertext + tag`
5. Hide the binary payload in the image using LSB steganography

### Decryption Flow (Decode)
1. Extract the binary payload from the image
2. Split into `salt`, `nonce`, and `ciphertext+tag`
3. Derive the key using Argon2id (salt + master password)
4. Decrypt and verify the authentication tag
5. If verification fails, the password is incorrect or the data is corrupted

### Database Index
- SQLCipher (encrypted SQLite)
- Stores: `id`, `name`, `filename`
- Key derived from the same master password
- Operates independently from the encoded images

---

## Project Structure

```
stegrust/
├── src/
│   ├── cli.rs         # Command-line interface
│   ├── crypto.rs      # Cryptography (Argon2id, AES-GCM)
│   ├── db/conn.rs     # SQLCipher database operations
│   ├── keyring.rs     # System keyring integration
│   ├── stego_bridge.rs # Python subprocess communication
│   └── main.rs        # Entry point
├── python/
│   └── stego.py       # LSB steganography bridge (Python)
├── Cargo.toml
└── README.md
```

---

## Limitations

- **Image format:** Only PNG is supported (lossless compression preserves LSB)
- **Capacity:** Limited by image resolution (1 bit per color channel per pixel)
- **Detection:** LSB steganography can be detected by statistical analysis
- **Master password:** The security of all data depends on its strength
- **Keyring:** Changing the system password may affect keyring access

---

## License

This project is licensed under the GN General Public License v3. See the `LICENSE` file for details.

---

## Contributing

Contributions are welcome. Please open an issue or submit a pull request on GitHub.

---

*Built with Rust and Python. Security through cryptography, discretion through steganography.*