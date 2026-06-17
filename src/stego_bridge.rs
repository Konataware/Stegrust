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

use std::process::{Command, Stdio};
use std::io::Write;
use std::path::{Path, PathBuf};
use anyhow::{Context, Result};

fn python_script_path() -> PathBuf {
    // all this code could be reduced with an install script
    // but we really don't want to do one
    if let Ok(exe_path) = std::env::current_exe() {
        let base = exe_path.parent().expect("Executable parent");
        let candidate = base.join("python/stego.py");
        if candidate.exists() {
            return candidate;
        }
    }
    let local_candidate = PathBuf::from("python/stego.py");
    if local_candidate.exists() {
        return local_candidate;
    }
    if let Ok(exe_path) = std::env::current_exe() {
        let base = exe_path.parent().expect("Executable parent");
        let candidate = base.join("../share/stegrust/python/stego.py");
        if candidate.exists() {
            return candidate;
        }
    }
    PathBuf::from("python/stego.py")
}

// hides the payload inside the input image calling the python script and returns an output file
pub fn stego_encode(input_path: &Path, output_path: &Path, payload: &[u8]) -> Result<()> {
    let script = python_script_path();
    if !script.exists() {
        anyhow::bail!("Python script not found at: {}", script.display());
    }

    let mut child = Command::new("python")
        .arg(&script)
        .arg("--encode")
        .arg("--input")
        .arg(input_path.as_os_str())
        .arg("--output")
        .arg(output_path.as_os_str())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .context("Failed to initiate python process")?;

    let mut stdin = child.stdin.take().expect("It was not possible to open STDIN");
    stdin.write_all(payload)?;
    stdin.flush()?;
    drop(stdin);

    let output = child.wait_with_output()?;
    if !output.status.success() {
        anyhow::bail!("Python encode failed (Exit code: {})", output.status);
    }
    Ok(())
}

// extracts the hidden bytes from the image to send to crypto.rs for extraction
pub fn stego_decode(input_path: &Path) -> Result<Vec<u8>> {
    let script = python_script_path();
    if !script.exists() {
        anyhow::bail!("Python script not found at: {}", script.display());
    }

    let child = Command::new("python")
        .arg(&script)
        .arg("--decode")
        .arg("--input")
        .arg(input_path.as_os_str())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("Failed to start python process")?;

    let output = child.wait_with_output()?;
    if !output.status.success() {
        anyhow::bail!("Python decode failed");
    }
    Ok(output.stdout)
}