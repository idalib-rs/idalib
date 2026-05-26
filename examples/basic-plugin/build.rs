fn main() -> Result<(), Box<dyn std::error::Error>> {
    let install = idalib_build::idalib_install_paths_with(false);
    if install.libs().iter().all(|p| p.exists()) {
        idalib_build::configure_linkage()?;
    } else {
        idalib_build::configure_idasdk_linkage();
    }
    Ok(())
}
