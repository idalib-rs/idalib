fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (_, ida_path, idalib_path) = idalib_build::idalib_install_paths_with(false);
    if !ida_path.exists() || !idalib_path.exists() {
        idalib_build::configure_idasdk_linkage();
    } else {
        idalib_build::configure_linkage()?;
    }
    Ok(())
}
