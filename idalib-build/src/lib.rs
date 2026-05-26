use std::env;
use std::path::{Path, PathBuf};

#[derive(Copy, Clone)]
enum Library {
    Ida,
    #[cfg_attr(feature = "plugin", allow(dead_code))]
    Idalib,
}

impl Library {
    fn link_name(self) -> &'static str {
        match self {
            Self::Ida => "ida",
            Self::Idalib => "idalib",
        }
    }

    fn install_filename(self) -> &'static str {
        match self {
            Self::Ida => {
                if cfg!(target_os = "linux") {
                    "libida.so"
                } else if cfg!(target_os = "macos") {
                    "libida.dylib"
                } else if cfg!(target_os = "windows") {
                    "ida.dll"
                } else {
                    panic!("unsupported platform");
                }
            }
            Self::Idalib => {
                if cfg!(target_os = "linux") {
                    "libidalib.so"
                } else if cfg!(target_os = "macos") {
                    "libidalib.dylib"
                } else if cfg!(target_os = "windows") {
                    "idalib.dll"
                } else {
                    panic!("unsupported platform");
                }
            }
        }
    }

    fn sdk_filename(self) -> &'static str {
        match self {
            Self::Ida => {
                if cfg!(target_os = "linux") {
                    "libida.so"
                } else if cfg!(target_os = "macos") {
                    "libida.dylib"
                } else if cfg!(target_os = "windows") {
                    "ida.lib"
                } else {
                    panic!("unsupported platform");
                }
            }
            Self::Idalib => {
                if cfg!(target_os = "linux") {
                    "libidalib.so"
                } else if cfg!(target_os = "macos") {
                    "libidalib.dylib"
                } else if cfg!(target_os = "windows") {
                    "idalib.lib"
                } else {
                    panic!("unsupported platform");
                }
            }
        }
    }
}

fn required_libraries() -> &'static [Library] {
    #[cfg(feature = "plugin")]
    {
        &[Library::Ida]
    }
    #[cfg(not(feature = "plugin"))]
    {
        &[Library::Ida, Library::Idalib]
    }
}

fn sdk_subdir() -> PathBuf {
    PathBuf::from(if cfg!(target_os = "linux") {
        "lib/x64_linux_64"
    } else if cfg!(target_os = "macos") {
        if cfg!(target_arch = "x86_64") {
            "lib/x64_mac_64"
        } else {
            "lib/arm64_mac_64"
        }
    } else if cfg!(target_os = "windows") {
        "lib/x64_win_64"
    } else {
        panic!("unsupported platform");
    })
}

fn default_install_candidates() -> Vec<PathBuf> {
    if cfg!(target_os = "macos") {
        vec![
            PathBuf::from("/Applications/IDA Professional 9.3.app/Contents/MacOS"),
            PathBuf::from("/Applications/IDA Home 9.3.app/Contents/MacOS"),
        ]
    } else if cfg!(target_os = "linux") {
        let home = env::var("HOME").unwrap_or_default();
        vec![
            PathBuf::from(&home).join("ida-pro-9.3"),
            PathBuf::from(&home).join("ida-home-9.3"),
        ]
    } else if cfg!(target_os = "windows") {
        vec![
            PathBuf::from(r"C:\Program Files\IDA Professional 9.3"),
            PathBuf::from(r"C:\Program Files\IDA Home 9.3"),
        ]
    } else {
        panic!("unsupported platform");
    }
}

fn resolve_default_install() -> PathBuf {
    let candidates = default_install_candidates();
    candidates
        .iter()
        .find(|root| {
            required_libraries()
                .iter()
                .all(|lib| root.join(lib.install_filename()).exists())
        })
        .cloned()
        .unwrap_or_else(|| {
            candidates
                .into_iter()
                .next()
                .expect("candidate list non-empty")
        })
}

pub struct SdkPaths {
    sdk: PathBuf,
    stubs: PathBuf,
    libs: Vec<PathBuf>,
}

impl SdkPaths {
    pub fn sdk(&self) -> &Path {
        &self.sdk
    }

    pub fn stubs(&self) -> &Path {
        &self.stubs
    }

    pub fn libs(&self) -> &[PathBuf] {
        &self.libs
    }
}

pub struct InstallPaths {
    root: PathBuf,
    libs: Vec<PathBuf>,
}

impl InstallPaths {
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn libs(&self) -> &[PathBuf] {
        &self.libs
    }
}

pub struct LibraryPaths {
    libs: Vec<PathBuf>,
}

impl LibraryPaths {
    pub fn libs(&self) -> &[PathBuf] {
        &self.libs
    }
}

pub fn idalib_sdk_paths() -> SdkPaths {
    idalib_sdk_paths_with(true)
}

pub fn idalib_sdk_paths_with(check: bool) -> SdkPaths {
    let sdk = PathBuf::from(env!("IDALIB_SDK"));
    let pro_h = sdk.join("include").join("pro.h");

    if check && !pro_h.exists() {
        let display = pro_h.display();
        panic!("`{display}` does not exist; SDK is not usable");
    }

    let stubs = sdk.join(sdk_subdir());
    let libs = required_libraries()
        .iter()
        .map(|lib| stubs.join(lib.sdk_filename()))
        .collect::<Vec<_>>();

    SdkPaths { sdk, stubs, libs }
}

pub fn idalib_install_paths() -> InstallPaths {
    idalib_install_paths_with(true)
}

pub fn idalib_install_paths_with(check: bool) -> InstallPaths {
    let root = env::var("IDADIR").map_or_else(|_| resolve_default_install(), PathBuf::from);

    let libs = required_libraries()
        .iter()
        .map(|lib| root.join(lib.install_filename()))
        .collect::<Vec<_>>();

    if check {
        for lib in &libs {
            if !lib.exists() {
                let display = lib.display();
                panic!("`{display}` does not exist; cannot find a compatible IDA installation");
            }
        }
    }

    InstallPaths { root, libs }
}

pub fn idalib_library_paths() -> LibraryPaths {
    idalib_library_paths_with(true)
}

pub fn idalib_library_paths_with(check: bool) -> LibraryPaths {
    LibraryPaths {
        libs: idalib_install_paths_with(check).libs,
    }
}

fn emit_link_flags(path: &Path) {
    let display = path.display();
    println!("cargo::rustc-link-search=native={display}");
    let kind = if cfg!(target_os = "windows") {
        "static"
    } else {
        "dylib"
    };
    for lib in required_libraries() {
        let name = lib.link_name();
        println!("cargo::rustc-link-lib={kind}={name}");
    }
}

pub fn configure_idalib_linkage() {
    emit_link_flags(idalib_install_paths().root());
}

pub fn configure_idasdk_linkage() {
    emit_link_flags(idalib_sdk_paths().stubs());

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

    let install = idalib_install_paths();
    let sdk = idalib_sdk_paths();
    let install_dir = install.root().display();
    let stubs_dir = sdk.stubs().display();

    for lib in required_libraries() {
        if cfg!(target_os = "linux") {
            let file = lib.install_filename();
            println!("cargo::rustc-link-arg=-Wl,-rpath,{install_dir},-L{stubs_dir},-l:{file}");
        } else if cfg!(target_os = "macos") {
            let name = lib.link_name();
            println!("cargo::rustc-link-arg=-Wl,-rpath,{install_dir},-L{stubs_dir},-l{name}");
        }
    }

    Ok(())
}
