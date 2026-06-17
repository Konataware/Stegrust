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
use keyring::Entry;
use rpassword::read_password;

pub const SERVICE: &str = "stegrust";
pub const USER: &str = "master_password";

pub fn get_master_password() -> Result<String> {
    let entry = Entry::new(SERVICE, USER)
        .context("Falha ao acessar keyring")?;
    
    if let Ok(pw) = entry.get_password() {
        return Ok(pw);
    }
    
    eprint!("Master password: ");
    let password = read_password()
        .context("Falha ao ler a senha")?;
    
    entry.set_password(&password)
        .context("Falha ao salvar senha no keyring")?;
    
    Ok(password)
}

// TODO - Implement this
// pub fn clear_master_password() -> Result<()> {
//     let entry = Entry::new(SERVICE, USER)
//         .context("Falha ao acessar keyring")?;
//     entry.delete_credential()  // ← aqui
//         .context("Falha ao remover senha do keyring")?;
//     Ok(())
// }