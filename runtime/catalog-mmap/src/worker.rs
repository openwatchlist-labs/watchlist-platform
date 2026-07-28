use crate::{CandidateMatch, MappedPackage, PackageView};
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;

pub const WORKER_PROTOCOL_VERSION: &str = "1";

pub fn run_worker(package: impl AsRef<Path>) -> Result<(), String> {
    let mapped = MappedPackage::open(package)?;
    let view = mapped.view()?;
    let info = view.info();
    let stdout = io::stdout();
    let mut output = stdout.lock();
    writeln!(
        output,
        "H\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        WORKER_PROTOCOL_VERSION,
        encode_hex(&info.component_id),
        encode_hex(&info.catalog_id),
        encode_hex(&info.catalog_version),
        info.catalog_checksum,
        encode_hex(&info.catalog_mode),
        info.package_sha256,
        info.record_count
    )
    .map_err(|error| format!("write worker hello: {error}"))?;
    output
        .flush()
        .map_err(|error| format!("flush worker hello: {error}"))?;

    let stdin = io::stdin();
    let reader = BufReader::new(stdin.lock());
    for line in reader.lines() {
        let line = line.map_err(|error| format!("read worker request: {error}"))?;
        if line.is_empty() {
            continue;
        }
        for response in handle_request_line(&view, &line) {
            writeln!(output, "{response}")
                .map_err(|error| format!("write worker response: {error}"))?;
        }
        output
            .flush()
            .map_err(|error| format!("flush worker response: {error}"))?;
    }
    Ok(())
}

pub fn handle_request_line(view: &PackageView<'_>, line: &str) -> Vec<String> {
    let fields = line.split('\t').collect::<Vec<_>>();
    let request_id = fields.get(1).copied().unwrap_or("unknown");
    match execute(view, &fields) {
        Ok(matches) => response_lines(request_id, &matches),
        Err(error) => vec![format!("X\t{}\t{}", request_id, encode_hex(&error))],
    }
}

fn execute(view: &PackageView<'_>, fields: &[&str]) -> Result<Vec<CandidateMatch>, String> {
    if fields.first().copied() != Some("Q") || fields.len() < 5 {
        return Err("invalid worker request framing".to_string());
    }
    validate_request_id(fields[1])?;
    let limit = parse_limit(fields[3])?;
    match fields[2] {
        "record" if fields.len() == 5 => {
            let value = decode_hex(fields[4])?;
            Ok(view.lookup_record(&value)?.into_iter().take(limit).collect())
        }
        "name" if fields.len() == 6 => {
            let prefix = match fields[4] {
                "0" => false,
                "1" => true,
                _ => return Err("name prefix flag must be 0 or 1".to_string()),
            };
            let value = decode_hex(fields[5])?;
            view.lookup_name(&value, prefix, limit)
        }
        "identifier" if fields.len() == 6 => {
            let identifier_type = decode_hex(fields[4])?;
            let value = decode_hex(fields[5])?;
            view.lookup_identifier(&identifier_type, &value, limit)
        }
        _ => Err("unsupported worker query".to_string()),
    }
}

fn response_lines(request_id: &str, matches: &[CandidateMatch]) -> Vec<String> {
    let mut lines = Vec::with_capacity(matches.len() + 2);
    lines.push(format!("B\t{}\t{}", request_id, matches.len()));
    for candidate in matches {
        lines.push(format!(
            "C\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            request_id,
            encode_hex(&candidate.record_id),
            encode_hex(&candidate.entity_type),
            encode_hex(&candidate.primary_name),
            encode_hex(&candidate.match_kind),
            encode_hex(&candidate.matched_value),
            encode_hex(&candidate.normalized_query)
        ));
    }
    lines.push(format!("E\t{}", request_id));
    lines
}

fn validate_request_id(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 96
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
    {
        return Err("invalid worker request id".to_string());
    }
    Ok(())
}

fn parse_limit(value: &str) -> Result<usize, String> {
    let limit = value
        .parse::<usize>()
        .map_err(|_| "worker limit must be an integer".to_string())?;
    if limit == 0 || limit > 10_000 {
        return Err("worker limit must be between 1 and 10000".to_string());
    }
    Ok(limit)
}

fn encode_hex(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value.as_bytes() {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn decode_hex(value: &str) -> Result<String, String> {
    if value.len() % 2 != 0 {
        return Err("hex field has odd length".to_string());
    }
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len() / 2);
    let mut index = 0usize;
    while index < bytes.len() {
        let high = hex_digit(bytes[index])?;
        let low = hex_digit(bytes[index + 1])?;
        decoded.push((high << 4) | low);
        index += 2;
    }
    String::from_utf8(decoded).map_err(|_| "hex field is not UTF-8".to_string())
}

fn hex_digit(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err("hex field contains a non-hexadecimal byte".to_string()),
    }
}
