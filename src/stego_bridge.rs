use std::process::{ Command, Stdio };
use std::io::Write;
use std::path::{ Path, PathBuf };
use anyhow::{ Context, Result };

fn python_script_path() -> PathBuf {
    if let Ok(exe_path) = std::env::current_exe() {
        let base = exe_path.parent().expect("Executable parent");
        let candidate = base.join("python/stego.py");
        if candidate.exists() {
            return candidate;
        }
    }
    PathBuf::from("python/stego.py")
}

pub fn stego_encode(input_path: &Path, output_path: &Path, payload: &[u8]) -> Result<()> {
    let script = python_script_path();
    if !script.exists() {
        anyhow::bail!("Python script has not been found at: {:?}", script)
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
        .context("[ERROR] Failed to initiate Python process.")?;

    let mut stdin = child.stdin.take().expect("[ERROR] It was not possible to open stdin");
    stdin.write_all(payload)?;
    stdin.flush()?;
    drop(stdin);

    let output = child.wait_with_output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("[ERROR] Python encode failed: {}", stderr);
    }
    Ok(())
}

pub fn stego_decode(input_path: &Path) -> Result<Vec<u8>> {
    let script = python_script_path();
    if !script.exists() {
        anyhow::bail!("[ERROR] Python script not found at {:?}", script);
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
        .context("[ERROR] Failed to initiate python process")?;

    let output = child.wait_with_output()?;
    if !output.status.success() {
        anyhow::bail!("[ERROR] Python decoding failed");
    }
    Ok(output.stdout)
}