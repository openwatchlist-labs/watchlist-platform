use openwatchlist_catalog_mmap::{compile, PackageView};

const INPUT: &[u8] = include_bytes!("../../../test/fixtures/runtime-mmap/ofac-fixture.owcin");
const GOLDEN: &[u8] = include_bytes!("../../../test/golden/runtime-mmap/ofac-fixture.owmmap");

#[test]
fn compiler_matches_go_reference_package() {
    let (artifact, info) = compile(INPUT).expect("compile fixture");
    assert_eq!(artifact, GOLDEN);
    assert_eq!(info.record_count, 3);
    assert_eq!(info.name_count, 8);
    assert_eq!(info.identifier_count, 3);
    assert_eq!(
        info.package_sha256,
        "8c5e581ad36807c15a2ae00c5cb4e8b7f9154e208b369ff3227617294a473367"
    );
}

#[test]
fn mapped_view_retrieves_candidates() {
    let view = PackageView::open(GOLDEN).expect("open fixture package");
    let exact = view
        .lookup_name("acme imports", false, 20)
        .expect("exact name lookup");
    assert_eq!(exact.len(), 1);
    assert_eq!(exact[0].record_id, "ofac:sdn:1001");
    assert_eq!(exact[0].match_kind, "alias");

    let prefix = view
        .lookup_name("acme", true, 20)
        .expect("prefix lookup");
    assert_eq!(prefix.len(), 1);
    assert_eq!(prefix[0].record_id, "ofac:sdn:1001");

    let identifier = view
        .lookup_identifier(
            "Legal Entity Identifier",
            "5493-001K-JTIIGC8Y1R12",
            20,
        )
        .expect("identifier lookup");
    assert_eq!(identifier.len(), 1);
    assert_eq!(identifier[0].record_id, "ofac:sdn:1001");

    let record = view
        .lookup_record("ofac:sdn:3003")
        .expect("record lookup")
        .expect("record exists");
    assert_eq!(record.primary_name, "Example Vessel");
}

#[test]
fn package_rejects_tampering() {
    let mut damaged = GOLDEN.to_vec();
    let last = damaged.len() - 1;
    damaged[last] ^= 0x01;
    assert!(PackageView::open(&damaged).is_err());
}
