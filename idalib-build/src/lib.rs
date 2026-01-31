use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Deserialize)]
struct IdaConfig {
    #[serde(rename = "Paths")]
    paths: Option<IdaConfigPaths>,
}

#[derive(Deserialize)]
struct IdaConfigPaths {
    #[serde(rename = "ida-install-dir")]
    ida_install_dir: Option<String>,
}

/// Try to read the IDA installation path from ~/.idapro/ida-config.json
fn read_ida_config() -> Option<PathBuf> {
    let home = env::var("HOME").ok()?;
    let config_path = PathBuf::from(home).join(".idapro").join("ida-config.json");
    let contents = fs::read_to_string(&config_path).ok()?;
    let config: IdaConfig = serde_json::from_str(&contents).ok()?;
    let path_str = config.paths?.ida_install_dir?;
    Some(PathBuf::from(path_str))
}

fn link_path() -> PathBuf {
    // First try to read from ida-config.json
    if let Some(mut path) = read_ida_config() {
        #[cfg(target_os = "macos")]
        if path.extension().map_or(false, |ext| ext == "app") {
            path.push("Contents");
            path.push("MacOS");
        }
        return path;
    }

    // Fall back to platform-specific defaults
    #[cfg(target_os = "macos")]
    return PathBuf::from("/Applications/IDA Professional 9.2.app/Contents/MacOS");

    #[cfg(target_os = "linux")]
    return PathBuf::from(env::var("HOME").unwrap()).join("ida-pro-9.2");

    #[cfg(target_os = "windows")]
    return PathBuf::from("C:\\Program Files\\IDA Professional 9.2");
}

pub fn idalib_sdk_paths() -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    idalib_sdk_paths_with(true)
}

pub fn idalib_sdk_paths_with(check: bool) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let sdk_path = PathBuf::from(env!("IDALIB_SDK"));
    let pro_h = sdk_path.join("include").join("pro.h");

    if check && !pro_h.exists() {
        panic!("`{}` does not exist; SDK is not usable", pro_h.display());
    }

    let (stubs_path, idalib, ida) = if cfg!(target_os = "linux") {
        let path = sdk_path.join("lib/x64_linux_gcc_64");
        let idalib = path.join("libidalib.so");
        let ida = path.join("libida.so");
        (path, idalib, ida)
    } else if cfg!(target_os = "macos") {
        let path = if cfg!(target_arch = "x86_64") {
            sdk_path.join("lib/x64_mac_clang_64")
        } else {
            sdk_path.join("lib/arm64_mac_clang_64")
        };
        let idalib = path.join("libidalib.dylib");
        let ida = path.join("libida.dylib");
        (path, idalib, ida)
    } else if cfg!(target_os = "windows") {
        let path = sdk_path.join("lib\\x64_win_vc_64");
        let idalib = path.join("idalib.lib");
        let ida = path.join("ida.lib");
        (path, idalib, ida)
    } else {
        panic!("unsupported platform");
    };

    (sdk_path, stubs_path, idalib, ida)
}

pub fn idalib_install_paths() -> (PathBuf, PathBuf, PathBuf) {
    idalib_install_paths_with(true)
}

pub fn idalib_install_paths_with(check: bool) -> (PathBuf, PathBuf, PathBuf) {
    let path = env::var("IDADIR").map_or_else(|_| link_path(), PathBuf::from);

    let (idalib, ida) = if cfg!(target_os = "linux") {
        (path.join("libidalib.so"), path.join("libida.so"))
    } else if cfg!(target_os = "macos") {
        (path.join("libidalib.dylib"), path.join("libida.dylib"))
    } else if cfg!(target_os = "windows") {
        (path.join("idalib.dll"), path.join("ida.dll"))
    } else {
        panic!("unsupported platform")
    };

    if check && !idalib.exists() {
        panic!(
            "`{}` does not exist; cannot find a compatible IDA Pro installation",
            idalib.display()
        );
    }

    (path, idalib, ida)
}

pub fn idalib_library_paths() -> (PathBuf, PathBuf) {
    idalib_library_paths_with(true)
}

pub fn idalib_library_paths_with(check: bool) -> (PathBuf, PathBuf) {
    let (_, idalib, ida) = idalib_install_paths_with(check);
    (idalib, ida)
}

fn configure_linkage_aux(path: &Path) {
    println!("cargo::rustc-link-search=native={}", path.display());
    if cfg!(target_os = "windows") {
        // .lib
        println!("cargo::rustc-link-lib=static=ida");
        println!("cargo::rustc-link-lib=static=idalib");
    } else {
        // .dylib/.so
        println!("cargo::rustc-link-lib=dylib=ida");
        println!("cargo::rustc-link-lib=dylib=idalib");
    }
}

pub fn configure_idalib_linkage() {
    let (install_path, _, _) = idalib_install_paths();
    configure_linkage_aux(&install_path);
}

pub fn configure_idasdk_linkage() {
    let (_, stubs_path, _, _) = idalib_sdk_paths();
    configure_linkage_aux(&stubs_path);

    if cfg!(target_os = "windows") {
        // FIXME: this seems to be required otherwise we report missing symbols and bail during
        // linking (seems to be due to autocxx)...
        println!("cargo::rustc-link-arg=/FORCE:UNRESOLVED");
    }
}

pub fn configure_linkage() -> anyhow::Result<()> {
    if cfg!(target_os = "windows") {
        configure_idasdk_linkage();
        return Ok(());
    }

    #[cfg(not(target_os = "windows"))]
    {
        let (install_path, _, _) = idalib_install_paths();
        let (_, stub_path, _, _) = idalib_sdk_paths();

        #[cfg(target_os = "linux")]
        {
            println!(
                "cargo::rustc-link-arg=-Wl,-rpath,{},-L{},-l:libida.so",
                install_path.display(),
                stub_path.display(),
            );
            println!(
                "cargo::rustc-link-arg=-Wl,-rpath,{},-L{},-l:libidalib.so",
                install_path.display(),
                stub_path.display(),
            );
        }

        #[cfg(target_os = "macos")]
        {
            println!(
                "cargo::rustc-link-arg=-Wl,-rpath,{},-L{},-lida",
                install_path.display(),
                stub_path.display(),
            );
            println!(
                "cargo::rustc-link-arg=-Wl,-rpath,{},-L{},-lidalib",
                install_path.display(),
                stub_path.display(),
            );
        }
    }

    Ok(())
}
