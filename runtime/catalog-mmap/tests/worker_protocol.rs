use openwatchlist_catalog_mmap::{compile, handle_request_line, PackageView, WORKER_PROTOCOL_VERSION};

const INPUT: &[u8] = include_bytes!("../../../test/fixtures/runtime-mmap/ofac-fixture.owcin");

#[test]
fn worker_protocol_returns_exact_candidates_and_errors() {
    assert_eq!(WORKER_PROTOCOL_VERSION, "1");
    let (package, _) = compile(INPUT).expect("compile fixture");
    let view = PackageView::open(&package).expect("open package");

    let query = hex("ACME IMPORTS");
    let lines = handle_request_line(&view, &format!("Q\treq-1\tname\t20\t0\t{query}"));
    assert_eq!(lines.first().map(String::as_str), Some("B\treq-1\t1"));
    assert!(lines[1].starts_with("C\treq-1\t"));
    assert_eq!(lines.last().map(String::as_str), Some("E\treq-1"));

    let error = handle_request_line(&view, "Q\treq-2\tunknown\t20\t00");
    assert_eq!(error.len(), 1);
    assert!(error[0].starts_with("X\treq-2\t"));
}

fn hex(value: &str) -> String {
    value.as_bytes().iter().map(|byte| format!("{byte:02x}")).collect()
}
