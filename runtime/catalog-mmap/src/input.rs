use std::collections::{BTreeMap, BTreeSet};

pub const MAGIC: &str = "OWCINPUT1";
pub const SCHEMA_VERSION: &str = "runtime-catalog-input/v1alpha1";
pub const EXPORTER_VERSION: &str = "runtime-catalog-input-exporter/v0.1.0";
pub const NORMALIZATION_PROFILE: &str = "openwatchlist-runtime-normalization/ascii-v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    pub schema_version: String,
    pub exporter_version: String,
    pub component_id: String,
    pub catalog_id: String,
    pub catalog_version: String,
    pub catalog_checksum: String,
    pub catalog_mode: String,
    pub source_manifest_id: String,
    pub source_schema_version: String,
    pub normalization_profile: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub record_id: String,
    pub entity_type: String,
    pub primary_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Name {
    pub record_id: String,
    pub kind: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identifier {
    pub record_id: String,
    pub identifier_type: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompilerInput {
    pub metadata: Metadata,
    pub records: Vec<Record>,
    pub names: Vec<Name>,
    pub identifiers: Vec<Identifier>,
}

pub fn parse(data: &[u8]) -> Result<CompilerInput, String> {
    let text = std::str::from_utf8(data).map_err(|_| "compiler input is not UTF-8".to_string())?;
    let mut lines = text.lines();
    if lines.next() != Some(MAGIC) {
        return Err("invalid compiler-input magic".to_string());
    }

    let mut metadata = BTreeMap::new();
    let mut records = Vec::new();
    let mut names = Vec::new();
    let mut identifiers = Vec::new();
    let mut ended = false;

    for (offset, line) in lines.enumerate() {
        let line_number = offset + 2;
        if ended {
            return Err(format!("line {line_number}: data follows end marker"));
        }
        let parts: Vec<&str> = line.split('\t').collect();
        match parts.first().copied().unwrap_or_default() {
            "M" => {
                if parts.len() != 3 {
                    return Err(format!("line {line_number}: invalid metadata field count"));
                }
                let value = decode_hex(parts[2])?;
                if metadata.insert(parts[1].to_string(), value).is_some() {
                    return Err(format!("line {line_number}: duplicate metadata key"));
                }
            }
            "R" => {
                if parts.len() != 4 {
                    return Err(format!("line {line_number}: invalid record field count"));
                }
                records.push(Record {
                    record_id: decode_hex(parts[1])?,
                    entity_type: decode_hex(parts[2])?,
                    primary_name: decode_hex(parts[3])?,
                });
            }
            "N" => {
                if parts.len() != 4 {
                    return Err(format!("line {line_number}: invalid name field count"));
                }
                names.push(Name {
                    record_id: decode_hex(parts[1])?,
                    kind: parts[2].to_string(),
                    value: decode_hex(parts[3])?,
                });
            }
            "I" => {
                if parts.len() != 4 {
                    return Err(format!("line {line_number}: invalid identifier field count"));
                }
                identifiers.push(Identifier {
                    record_id: decode_hex(parts[1])?,
                    identifier_type: decode_hex(parts[2])?,
                    value: decode_hex(parts[3])?,
                });
            }
            "E" => {
                if parts.len() != 4 {
                    return Err(format!("line {line_number}: invalid end field count"));
                }
                let expected = [records.len(), names.len(), identifiers.len()];
                for index in 0..3 {
                    let actual = parts[index + 1]
                        .parse::<usize>()
                        .map_err(|_| format!("line {line_number}: invalid count"))?;
                    if actual != expected[index] {
                        return Err(format!("line {line_number}: count mismatch"));
                    }
                }
                ended = true;
            }
            _ => return Err(format!("line {line_number}: unknown record type")),
        }
    }
    if !ended {
        return Err("missing compiler-input end marker".to_string());
    }

    let required = [
        "schema_version",
        "exporter_version",
        "component_id",
        "catalog_id",
        "catalog_version",
        "catalog_checksum",
        "catalog_mode",
        "source_manifest_id",
        "source_schema_version",
        "normalization_profile",
    ];
    if metadata.len() != required.len() || required.iter().any(|key| !metadata.contains_key(*key)) {
        return Err("compiler-input metadata key set mismatch".to_string());
    }
    let take = |key: &str| metadata.get(key).cloned().unwrap_or_default();
    let input = CompilerInput {
        metadata: Metadata {
            schema_version: take("schema_version"),
            exporter_version: take("exporter_version"),
            component_id: take("component_id"),
            catalog_id: take("catalog_id"),
            catalog_version: take("catalog_version"),
            catalog_checksum: take("catalog_checksum"),
            catalog_mode: take("catalog_mode"),
            source_manifest_id: take("source_manifest_id"),
            source_schema_version: take("source_schema_version"),
            normalization_profile: take("normalization_profile"),
        },
        records,
        names,
        identifiers,
    };
    validate(&input)?;
    Ok(input)
}

fn validate(input: &CompilerInput) -> Result<(), String> {
    let metadata = &input.metadata;
    if metadata.schema_version != SCHEMA_VERSION
        || metadata.exporter_version != EXPORTER_VERSION
        || metadata.normalization_profile != NORMALIZATION_PROFILE
    {
        return Err("unsupported compiler-input contract".to_string());
    }
    if !metadata.component_id.starts_with("catalog_component_")
        || metadata.catalog_id.is_empty()
        || metadata.catalog_version.is_empty()
        || metadata.source_manifest_id.is_empty()
        || metadata.source_schema_version.is_empty()
    {
        return Err("incomplete compiler-input metadata".to_string());
    }
    if metadata.catalog_checksum.len() != 64
        || !metadata.catalog_checksum.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("catalog checksum must be hexadecimal SHA-256".to_string());
    }
    if metadata.catalog_mode != "official_list" && metadata.catalog_mode != "provider" {
        return Err("unsupported catalog mode".to_string());
    }
    if input.records.is_empty() {
        return Err("compiler input has no records".to_string());
    }

    let mut record_ids = BTreeSet::new();
    let mut previous = "";
    for record in &input.records {
        if record.record_id.is_empty()
            || record.entity_type.is_empty()
            || record.primary_name.trim().is_empty()
            || (!previous.is_empty() && record.record_id.as_str() <= previous)
        {
            return Err("records must be complete, unique, and sorted".to_string());
        }
        previous = &record.record_id;
        record_ids.insert(record.record_id.as_str());
    }

    let mut previous_key = String::new();
    let mut primary_counts = BTreeMap::<&str, usize>::new();
    for name in &input.names {
        if !record_ids.contains(name.record_id.as_str())
            || (name.kind != "primary" && name.kind != "alias")
            || name.value.trim().is_empty()
        {
            return Err("invalid name entry".to_string());
        }
        let key = format!("{}\0{}\0{}", name.record_id, name.kind, name.value);
        if !previous_key.is_empty() && key <= previous_key {
            return Err("name entries must be unique and sorted".to_string());
        }
        previous_key = key;
        if name.kind == "primary" {
            *primary_counts.entry(name.record_id.as_str()).or_default() += 1;
        }
    }
    for record_id in record_ids.iter() {
        if primary_counts.get(record_id).copied() != Some(1) {
            return Err("each record must have one primary index name".to_string());
        }
    }

    previous_key.clear();
    for identifier in &input.identifiers {
        if !record_ids.contains(identifier.record_id.as_str())
            || identifier.identifier_type.is_empty()
            || identifier.value.is_empty()
        {
            return Err("invalid identifier entry".to_string());
        }
        let key = format!(
            "{}\0{}\0{}",
            identifier.record_id, identifier.identifier_type, identifier.value
        );
        if !previous_key.is_empty() && key <= previous_key {
            return Err("identifier entries must be unique and sorted".to_string());
        }
        previous_key = key;
    }
    Ok(())
}

fn decode_hex(value: &str) -> Result<String, String> {
    if value.len() % 2 != 0 {
        return Err("invalid hexadecimal field".to_string());
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    let raw = value.as_bytes();
    for index in (0..raw.len()).step_by(2) {
        let high = hex_nibble(raw[index])?;
        let low = hex_nibble(raw[index + 1])?;
        bytes.push((high << 4) | low);
    }
    String::from_utf8(bytes).map_err(|_| "hexadecimal field is not UTF-8".to_string())
}

fn hex_nibble(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err("invalid hexadecimal field".to_string()),
    }
}
