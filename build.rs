fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| "unknown".to_string());

    if target_os == "windows" {
        let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR")?);
        let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());

        let Ok(cargo_target_dir) = extract_matching_parent_dir(&out_dir, &profile) else {
            println!("cargo:warning=Could not find target directory");
            return Ok(());
        };
        // The wintun crate's root directory
        let crate_dir = get_crate_dir("wintun")?;

        // The path to the DLL file, relative to the crate root, depending on the target architecture
        let dll_path = get_wintun_bin_relative_path()?;
        let src_path = crate_dir.join(dll_path);

        let dst_path = cargo_target_dir.join("examples/wintun.dll");

        // Copy to the target directory
        std::fs::copy(src_path, &dst_path)?;

        // Set the modified time to the current time, or the publishing process will fail.
        let file = std::fs::OpenOptions::new().write(true).open(&dst_path)?;
        file.set_modified(std::time::SystemTime::now())?;
    }
    Ok(())
}

fn extract_matching_parent_dir<P: AsRef<std::path::Path>>(path: P, match_name: &str) -> std::io::Result<std::path::PathBuf> {
    let target_dir = std::path::Path::new(path.as_ref())
        .ancestors()
        .find(|p| p.file_name().map(|n| *n == *match_name).unwrap_or(false))
        .ok_or(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("No parent directory matching '{match_name}'"),
        ))?;
    Ok(target_dir.to_path_buf())
}

fn get_wintun_bin_relative_path() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH")?;

    let dll_path = match target_arch.as_str() {
        "x86" => "wintun/bin/x86/wintun.dll",
        "x86_64" => "wintun/bin/amd64/wintun.dll",
        "arm" => "wintun/bin/arm/wintun.dll",
        "aarch64" => "wintun/bin/arm64/wintun.dll",
        _ => return Err("Unsupported architecture".into()),
    };

    Ok(dll_path.into())
}

fn get_crate_dir(crate_name: &str) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let output = std::process::Command::new("cargo")
        .arg("metadata")
        .arg("--format-version=1")
        .output()?;

    let metadata = serde_json::from_slice::<serde_json::Value>(&output.stdout)?;
    let packages = metadata["packages"].as_array().ok_or("packages")?;

    let mut crate_dir = None;

    for package in packages {
        let name = package["name"].as_str().ok_or("name")?;
        if name == crate_name {
            let path = package["manifest_path"].as_str().ok_or("manifest_path")?;
            let path = std::path::PathBuf::from(path);
            crate_dir = Some(path.parent().ok_or("parent")?.to_path_buf());
            break;
        }
    }
    Ok(crate_dir.ok_or("crate_dir")?)
}
