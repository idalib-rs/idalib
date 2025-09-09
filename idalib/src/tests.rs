use std::io::prelude::*;
use std::path::{Path, PathBuf};

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

fn read_file(path: &Path) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut f = std::fs::File::open(&path).unwrap();
        f.read_to_end(&mut buf).unwrap();
    }
    buf
}

pub fn get_test_file_buf(filename: &str) -> Vec<u8> {
    let path = get_test_file_path(filename);
    read_file(&path)
}
