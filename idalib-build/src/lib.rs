use std::env;
use std::path::{Path, PathBuf};

/// Returns the OS of the target being built (e.g., `linux`).
fn target_os() -> String {
    env::var("CARGO_CFG_TARGET_OS").expect("CARGO_CFG_TARGET_OS should be set")
}

/// Returns the architecture of the target being built (e.g., `aarch64`).
fn target_arch() -> String {
    env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH should be set")
}

fn link_path() -> PathBuf {
    match target_os().as_str() {
        "macos" => PathBuf::from("/Applications/IDA Professional 9.4.app/Contents/MacOS"),
        "linux" => PathBuf::from(env::var("HOME").unwrap()).join("ida-pro-9.4"),
        "windows" => PathBuf::from("C:\\Program Files\\IDA Professional 9.4"),
        _ => panic!("unsupported platform"),
    }
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

    let (stubs_dir, idalib_name, ida_name) = match (target_os().as_str(), target_arch().as_str()) {
        ("linux", "aarch64") => ("arm64_linux_64", "libidalib.so", "libida.so"),
        ("linux", _) => ("x64_linux_64", "libidalib.so", "libida.so"),
        ("macos", "x86_64") => ("x64_mac_64", "libidalib.dylib", "libida.dylib"),
        ("macos", _) => ("arm64_mac_64", "libidalib.dylib", "libida.dylib"),
        ("windows", "aarch64") => ("arm64_win_64", "idalib.lib", "ida.lib"),
        ("windows", _) => ("x64_win_64", "idalib.lib", "ida.lib"),
        _ => panic!("unsupported platform"),
    };

    let stubs_path = sdk_path.join("lib").join(stubs_dir);
    let idalib = stubs_path.join(idalib_name);
    let ida = stubs_path.join(ida_name);

    (sdk_path, stubs_path, idalib, ida)
}

pub fn idalib_install_paths() -> (PathBuf, PathBuf, PathBuf) {
    idalib_install_paths_with(true)
}

pub fn idalib_install_paths_with(check: bool) -> (PathBuf, PathBuf, PathBuf) {
    let path = env::var("IDADIR").map_or_else(|_| link_path(), PathBuf::from);

    let (idalib, ida) = match target_os().as_str() {
        "linux" => (path.join("libidalib.so"), path.join("libida.so")),
        "macos" => (path.join("libidalib.dylib"), path.join("libida.dylib")),
        "windows" => (path.join("idalib.dll"), path.join("ida.dll")),
        _ => panic!("unsupported platform"),
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
    if target_os() == "windows" {
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

    if target_os() == "windows" {
        // FIXME: this seems to be required otherwise we report missing symbols and bail during
        // linking (seems to be due to autocxx)...
        println!("cargo::rustc-link-arg=/FORCE:UNRESOLVED");
    }
}

pub fn configure_linkage() -> anyhow::Result<()> {
    let os = target_os();

    if os == "windows" {
        configure_idasdk_linkage();
        return Ok(());
    }

    let (install_path, _, _) = idalib_install_paths();
    let (_, stub_path, _, _) = idalib_sdk_paths();

    let libs = if os == "linux" {
        "-l:libida.so,-l:libidalib.so"
    } else {
        "-lida,-lidalib"
    };

    println!(
        "cargo::rustc-link-arg=-Wl,-rpath,{}",
        install_path.display()
    );
    println!("cargo::rustc-link-arg=-Wl,-L{},{libs}", stub_path.display());

    Ok(())
}
