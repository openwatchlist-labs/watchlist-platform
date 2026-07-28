use std::fs;
use std::path::PathBuf;

fn escape_json(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn string_array(value: &str) -> String {
    let values: Vec<String> = value
        .split('|')
        .filter(|item| !item.is_empty())
        .map(|item| format!("\"{}\"", escape_json(item)))
        .collect();
    format!("[{}]", values.join(","))
}

fn identifier_array(value: &str) -> String {
    let values: Vec<String> = value
        .split('|')
        .filter(|item| !item.is_empty())
        .map(|item| {
            let mut parts = item.splitn(2, '=');
            let kind = parts.next().unwrap_or("");
            let identifier = parts.next().unwrap_or("");
            format!(
                "{{\"type\":\"{}\",\"value\":\"{}\"}}",
                escape_json(kind),
                escape_json(identifier)
            )
        })
        .collect();
    format!("[{}]", values.join(","))
}

#[test]
fn rust_reference_emits_byte_identical_projection_payload() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo = manifest_dir.join("../..");
    let vector_path = repo.join("test/fixtures/projection-package/projection-conformance.tsv");
    let package_path = repo.join("test/fixtures/projection-package/packages/b652a63ffd2c8ed73dd40e8fb3530670ad49798fb3140fe3de8ac02ec12f7167/projections.json");
    let vector = fs::read_to_string(vector_path).expect("read conformance vector");
    let mut candidates = Vec::new();
    for line in vector.lines().filter(|line| !line.trim().is_empty()) {
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 6, "invalid conformance vector row");
        let mut candidate = format!("{{\"candidate_id\":\"{}\"", escape_json(fields[0]));
        if !fields[1].is_empty() {
            candidate.push_str(&format!(",\"names\":{}", string_array(fields[1])));
        }
        if !fields[2].is_empty() {
            candidate.push_str(&format!(",\"identifiers\":{}", identifier_array(fields[2])));
        }
        if !fields[3].is_empty() {
            candidate.push_str(&format!(",\"countries\":{}", string_array(fields[3])));
        }
        if !fields[4].is_empty() {
            candidate.push_str(&format!(",\"dates_of_birth\":{}", string_array(fields[4])));
        }
        if !fields[5].is_empty() {
            candidate.push_str(&format!(",\"entity_type\":\"{}\"", escape_json(fields[5])));
        }
        candidate.push('}');
        candidates.push(candidate);
    }
    let emitted = format!(
        "{{\"schema_version\":\"openwatchlist.candidate-projection-registry.v1\",\"candidates\":[{}]}}\n",
        candidates.join(",")
    );
    let golden = fs::read_to_string(package_path).expect("read Go projection payload");
    assert_eq!(emitted.as_bytes(), golden.as_bytes());
}
