use tempdir::TempDir;

use idalib::idb::IDB;
use idalib::segment::{self, SegmentPermissions, SegmentType};
#[path = "../src/tests.rs"]
mod tests;

#[derive(Debug, Clone, PartialEq)]
struct ExpectedSegment {
    name: String,
    start_addr: u64,
    end_addr: u64,
    segment_type: SegmentType,
    permissions: SegmentPermissions,
    bitness: usize,
    is_code: bool,
    is_data: bool,
    is_executable: bool,
    is_writable: bool,
    is_readable: bool,
    is_visible: bool,
}

fn test_segments() {
    const FILENAME: &str = "Practical Malware Analysis Lab 01-01.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDB::open(dst).unwrap();

    let expected_segments: Vec<ExpectedSegment> = vec![
        ExpectedSegment {
            name: ".text".to_string(),
            start_addr: 0x10001000,
            end_addr: 0x10002000,
            segment_type: SegmentType::CODE,
            permissions: SegmentPermissions::EXEC | SegmentPermissions::READ,
            bitness: 1,
            is_code: true,
            is_data: false,
            is_executable: true,
            is_writable: false,
            is_readable: true,
            is_visible: true,
        },
        ExpectedSegment {
            name: ".idata".to_string(),
            start_addr: 0x10002000,
            end_addr: 0x1000205C,
            segment_type: SegmentType::XTRN,
            permissions: SegmentPermissions::READ,
            bitness: 1,
            is_code: false,
            is_data: false,
            is_executable: false,
            is_writable: false,
            is_readable: true,
            is_visible: true,
        },
        ExpectedSegment {
            name: ".rdata".to_string(),
            start_addr: 0x1000205C,
            end_addr: 0x10026000,
            segment_type: SegmentType::DATA,
            permissions: SegmentPermissions::READ,
            bitness: 1,
            is_code: false,
            is_data: true,
            is_executable: false,
            is_writable: false,
            is_readable: true,
            is_visible: true,
        },
        ExpectedSegment {
            name: ".data".to_string(),
            start_addr: 0x10026000,
            end_addr: 0x10027000,
            segment_type: SegmentType::DATA,
            permissions: SegmentPermissions::WRITE | SegmentPermissions::READ,
            bitness: 1,
            is_code: false,
            is_data: true,
            is_executable: false,
            is_writable: true,
            is_readable: true,
            is_visible: true,
        },
    ];

    let mut actual_segments = Vec::new();
    for (i, (_, segment)) in idb.segments().enumerate() {
        let name = segment.name().unwrap_or(format!("unnamed_{}", i));
        actual_segments.push(ExpectedSegment {
            name: name.clone(),
            start_addr: segment.start_address(),
            end_addr: segment.end_address(),
            segment_type: segment.r#type(),
            permissions: segment.permissions(),
            bitness: segment.bitness(),
            is_code: segment.is_code_segment(),
            is_data: segment.is_data_segment(),
            is_executable: segment.permissions().is_executable(),
            is_writable: segment.permissions().is_writable(),
            is_readable: segment.permissions().is_readable(),
            is_visible: segment.is_visible(),
        });
    }

    assert_eq!(
        expected_segments.len(),
        actual_segments.len(),
        "Expected {} segments, found {}",
        expected_segments.len(),
        actual_segments.len()
    );

    for (expected, actual) in expected_segments.iter().zip(actual_segments.iter()) {
        assert_eq!(expected.name, actual.name, "Segment name mismatch");
        assert_eq!(
            expected.start_addr, actual.start_addr,
            "Start address mismatch for segment {}",
            expected.name
        );
        assert_eq!(
            expected.end_addr, actual.end_addr,
            "End address mismatch for segment {}",
            expected.name
        );
        assert_eq!(
            expected.segment_type, actual.segment_type,
            "Segment type mismatch for segment {}",
            expected.name
        );
        assert_eq!(
            expected.permissions, actual.permissions,
            "Permissions mismatch for segment {}",
            expected.name
        );
        assert_eq!(
            expected.bitness, actual.bitness,
            "Bitness mismatch for segment {}",
            expected.name
        );
        assert_eq!(
            expected.is_code, actual.is_code,
            "is_code mismatch for segment {}",
            expected.name
        );
        assert_eq!(
            expected.is_data, actual.is_data,
            "is_data mismatch for segment {}",
            expected.name
        );
        assert_eq!(
            expected.is_executable, actual.is_executable,
            "is_executable mismatch for segment {}",
            expected.name
        );
        assert_eq!(
            expected.is_writable, actual.is_writable,
            "is_writable mismatch for segment {}",
            expected.name
        );
        assert_eq!(
            expected.is_readable, actual.is_readable,
            "is_readable mismatch for segment {}",
            expected.name
        );
        assert_eq!(
            expected.is_visible, actual.is_visible,
            "is_visible mismatch for segment {}",
            expected.name
        );
    }
}

fn test_fileregion_functions() {
    const FILENAME: &str = "Practical Malware Analysis Lab 01-01.dll_";
    let dir = TempDir::new("idalib-rs-tests").unwrap();
    let dst = dir.path().join(FILENAME);
    let src = tests::get_test_file_path(FILENAME);
    std::fs::copy(&src, &dst).unwrap();

    let idb = IDB::open(dst).unwrap();

    // Test get_fileregion_offset for a known address
    // .text segment starts at 0x10001000
    let offset = idb.get_fileregion_offset(0x10001000);
    assert!(
        offset >= 0,
        "get_fileregion_offset should return a non-negative offset for valid address"
    );

    // Test get_fileregion_ea with the offset we just got
    let ea = idb.get_fileregion_ea(offset);
    assert_eq!(
        ea, 0x10001000,
        "get_fileregion_ea should map back to original address"
    );

    // Test with unmappable address (should return -1)
    let invalid_offset = idb.get_fileregion_offset(0x99999999);
    assert_eq!(
        invalid_offset, -1,
        "get_fileregion_offset should return -1 for unmappable address"
    );
}

fn main() {
    test_segments();
    test_fileregion_functions();
}
