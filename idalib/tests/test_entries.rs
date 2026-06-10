use std::path::PathBuf;

use tempdir::TempDir;

use idalib::entry;
use idalib::idb::IDB;
#[path = "../src/tests.rs"]
mod tests;

fn test_entry_point_count() {
    // Practical Malware Analysis Lab 01-01.dll_ has no named exports but
    // IDA records its AddressOfEntryPoint as an entry point.
    const FILENAME: &str = "Practical Malware Analysis Lab 01-01.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDB::open(dst).unwrap();

    let entries: Vec<_> = idb.entries().collect();
    // At minimum the PE entry point should be present.
    assert!(
        !entries.is_empty(),
        "expected at least one entry point (PE entry point)"
    );

    for e in &entries {
        assert!(
            e.address() != 0,
            "entry point with ordinal {} has zero address",
            e.ordinal()
        );
        assert!(
            e.ordinal() != 0,
            "entry point at {:#x} has zero ordinal",
            e.address()
        );
    }
}

fn test_export_enumeration() {
    // Practical Malware Analysis Lab 03-02.dll_ has five named exports.
    const FILENAME: &str = "Practical Malware Analysis Lab 03-02.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDB::open(dst).unwrap();

    let entries: Vec<_> = idb.entries().collect();

    // From the PE export directory:
    //   ord=1 addr=0x10004706 name="Install"
    //   ord=2 addr=0x10003196 name="ServiceMain"
    //   ord=3 addr=0x10004b18 name="UninstallService"
    //   ord=4 addr=0x10004b0b name="installA"
    //   ord=5 addr=0x10004c2b name="uninstallA"
    //
    // IDA may also add the PE entry point itself, so we check that the
    // named exports are a *subset* rather than the full set.
    let expected = [
        ("Install", 0x10004706, 1u64),
        ("ServiceMain", 0x10003196, 2),
        ("UninstallService", 0x10004b18, 3),
        ("installA", 0x10004b0b, 4),
        ("uninstallA", 0x10004c2b, 5),
    ];

    for (exp_name, exp_addr, exp_ord) in &expected {
        let found = entries
            .iter()
            .find(|e| e.name().as_deref() == Some(*exp_name));
        assert!(
            found.is_some(),
            "did not find expected export `{exp_name}` in {entries:?}"
        );
        let e = found.unwrap();
        assert_eq!(e.address(), *exp_addr, "address mismatch for `{exp_name}`");
        assert_eq!(e.ordinal(), *exp_ord, "ordinal mismatch for `{exp_name}`");
        assert!(
            e.forwarder().is_none(),
            "`{exp_name}` should not be a forwarded export"
        );
    }
}

fn test_entry_module_function() {
    // Verify that `entry::entries(&idb)` works (not just `idb.entries()`).
    const FILENAME: &str = "Practical Malware Analysis Lab 01-01.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDB::open(dst).unwrap();

    let via_module: Vec<_> = entry::entries(&idb).collect();
    let via_method: Vec<_> = idb.entries().collect();
    assert_eq!(via_module.len(), via_method.len());
}

fn main() {
    test_entry_point_count();
    test_export_enumeration();
    test_entry_module_function();
}
