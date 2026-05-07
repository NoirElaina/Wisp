use std::{env, path::{Path, PathBuf}};

fn main() {
    #[cfg(target_os = "windows")]
    configure_npcap_link_search();

    tauri_build::build()
}

#[cfg(target_os = "windows")]
fn configure_npcap_link_search() {
    println!("cargo:rerun-if-env-changed=NPCAP_SDK_DIR");

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "x86_64".to_string());
    let arch_dir = match target_arch.as_str() {
        "x86_64" => "x64",
        "aarch64" => "ARM64",
        "x86" => "Lib",
        _ => "x64",
    };

    let mut candidates = Vec::new();

    if let Ok(root) = env::var("NPCAP_SDK_DIR") {
        let root = PathBuf::from(root);
        candidates.push(root.join("Lib").join(arch_dir));
        candidates.push(root.join("Lib"));
    }

    candidates.push(PathBuf::from(r"C:\Program Files\Npcap SDK\Lib").join(arch_dir));
    candidates.push(PathBuf::from(r"C:\Program Files\Npcap SDK\Lib"));
    candidates.push(PathBuf::from(r"C:\Program Files (x86)\Npcap SDK\Lib").join(arch_dir));
    candidates.push(PathBuf::from(r"C:\Program Files (x86)\Npcap SDK\Lib"));

    let mut configured = false;

    for candidate in candidates {
        if contains_wpcap_lib(&candidate) {
            println!("cargo:rustc-link-search=native={}", candidate.display());
            configured = true;
        }
    }

    if !configured {
        println!(
            "cargo:warning=Npcap SDK library path was not found automatically. \
Set NPCAP_SDK_DIR or install the SDK to C:\\Program Files\\Npcap SDK."
        );
    }
}

#[cfg(target_os = "windows")]
fn contains_wpcap_lib(path: &Path) -> bool {
    path.join("wpcap.lib").exists()
}
