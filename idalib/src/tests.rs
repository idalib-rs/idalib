use std::path::PathBuf;

/// Fetch the file system path of the given test file.
///
/// Found in idalib-root/tests/
/// Files include:
///   - Practical Malware Analysis Lab 01-01.dll_
pub fn get_test_file_path(filename: &str) -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("..");
    d.push("tests");
    d.push(filename);
    d
}
