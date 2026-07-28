use crate::input::{self, CompilerInput};
use crate::sha256;
use std::collections::{BTreeMap, BTreeSet};

pub const MAGIC: &[u8; 8] = b"OWMMAP01";
pub const FORMAT_VERSION: u32 = 1;
pub const HEADER_SIZE: usize = 64;
pub const DIRECTORY_ENTRY_SIZE: usize = 32;
pub const PACKAGE_SCHEMA_VERSION: &str = "memory-mapped-catalog/v1alpha1";
pub const COMPILER_VERSION: &str = "catalog-mmap-compiler/v0.1.0";

const SECTION_METADATA: u32 = 1;
const SECTION_STRINGS: u32 = 2;
const SECTION_RECORDS: u32 = 3;
const SECTION_NAMES: u32 = 4;
const SECTION_IDENTIFIERS: u32 = 5;
const METADATA_FIELD_COUNT: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageInfo {
    pub schema_version: String,
    pub compiler_version: String,
    pub format_version: u32,
    pub component_id: String,
    pub catalog_id: String,
    pub catalog_version: String,
    pub catalog_checksum: String,
    pub catalog_mode: String,
    pub source_manifest_id: String,
    pub source_schema_version: String,
    pub normalization_profile: String,
    pub input_sha256: String,
    pub payload_sha256: String,
    pub package_sha256: String,
    pub package_length: u64,
    pub record_count: u64,
    pub name_count: u64,
    pub identifier_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateMatch {
    pub record_id: String,
    pub entity_type: String,
    pub primary_name: String,
    pub match_kind: String,
    pub matched_value: String,
    pub normalized_query: String,
}

#[derive(Clone, Copy, Debug)]
struct StringRef {
    offset: u64,
    length: u32,
}

#[derive(Debug)]
struct StringPool {
    data: Vec<u8>,
    refs: BTreeMap<String, StringRef>,
}

impl StringPool {
    fn new() -> Self {
        Self {
            data: Vec::new(),
            refs: BTreeMap::new(),
        }
    }

    fn intern(&mut self, value: &str) -> Result<StringRef, String> {
        if let Some(existing) = self.refs.get(value) {
            return Ok(*existing);
        }
        let offset = u64::try_from(self.data.len()).map_err(|_| "string pool overflow")?;
        let length = u32::try_from(value.as_bytes().len()).map_err(|_| "string too long")?;
        self.data.extend_from_slice(value.as_bytes());
        let reference = StringRef { offset, length };
        self.refs.insert(value.to_string(), reference);
        Ok(reference)
    }
}

#[derive(Debug)]
struct SectionData {
    kind: u32,
    entry_size: u32,
    count: u64,
    bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
struct Section {
    entry_size: u32,
    offset: usize,
    length: usize,
    count: usize,
}

pub fn compile(input_bytes: &[u8]) -> Result<(Vec<u8>, PackageInfo), String> {
    let parsed = input::parse(input_bytes)?;
    compile_parsed(input_bytes, &parsed)
}

fn compile_parsed(input_bytes: &[u8], parsed: &CompilerInput) -> Result<(Vec<u8>, PackageInfo), String> {
    let input_digest = sha256::digest(input_bytes);
    let input_sha256 = sha256::hex(&input_digest);
    let mut pool = StringPool::new();
    let mut record_index = BTreeMap::<String, u32>::new();
    let mut records = Vec::with_capacity(parsed.records.len() * 32);

    for (index, record) in parsed.records.iter().enumerate() {
        let index = u32::try_from(index).map_err(|_| "record count exceeds u32")?;
        record_index.insert(record.record_id.clone(), index);
        let record_id = pool.intern(&record.record_id)?;
        let primary_name = pool.intern(&record.primary_name)?;
        let mut entry = [0u8; 32];
        put_u64(&mut entry[0..8], record_id.offset);
        put_u32(&mut entry[8..12], record_id.length);
        put_u64(&mut entry[12..20], primary_name.offset);
        put_u32(&mut entry[20..24], primary_name.length);
        entry[24] = entity_type_code(&record.entity_type)
            .ok_or_else(|| format!("unsupported entity type {:?}", record.entity_type))?;
        records.extend_from_slice(&entry);
    }

    #[derive(Debug)]
    struct NameItem {
        normalized: String,
        value: String,
        record: u32,
        kind: u8,
    }
    let mut names = Vec::with_capacity(parsed.names.len());
    for name in &parsed.names {
        let normalized = normalize_name(&name.value);
        if normalized.is_empty() {
            continue;
        }
        let record = *record_index
            .get(&name.record_id)
            .ok_or_else(|| "name references unknown record".to_string())?;
        let kind = if name.kind == "primary" { 1 } else { 2 };
        names.push(NameItem {
            normalized,
            value: name.value.clone(),
            record,
            kind,
        });
    }
    names.sort_by(|left, right| {
        left.normalized
            .cmp(&right.normalized)
            .then(left.record.cmp(&right.record))
            .then(left.kind.cmp(&right.kind))
            .then(left.value.cmp(&right.value))
    });
    let mut name_bytes = Vec::with_capacity(names.len() * 32);
    for item in &names {
        let normalized = pool.intern(&item.normalized)?;
        let value = pool.intern(&item.value)?;
        let mut entry = [0u8; 32];
        put_u64(&mut entry[0..8], normalized.offset);
        put_u32(&mut entry[8..12], normalized.length);
        put_u64(&mut entry[12..20], value.offset);
        put_u32(&mut entry[20..24], value.length);
        put_u32(&mut entry[24..28], item.record);
        entry[28] = item.kind;
        name_bytes.extend_from_slice(&entry);
    }

    #[derive(Debug)]
    struct IdentifierItem {
        identifier_type: String,
        normalized: String,
        value: String,
        record: u32,
    }
    let mut identifiers = Vec::with_capacity(parsed.identifiers.len());
    for identifier in &parsed.identifiers {
        let identifier_type = normalize_type(&identifier.identifier_type);
        let normalized = normalize_identifier(&identifier.value);
        if identifier_type.is_empty() || normalized.is_empty() {
            continue;
        }
        let record = *record_index
            .get(&identifier.record_id)
            .ok_or_else(|| "identifier references unknown record".to_string())?;
        identifiers.push(IdentifierItem {
            identifier_type,
            normalized,
            value: identifier.value.clone(),
            record,
        });
    }
    identifiers.sort_by(|left, right| {
        left.identifier_type
            .cmp(&right.identifier_type)
            .then(left.normalized.cmp(&right.normalized))
            .then(left.record.cmp(&right.record))
            .then(left.value.cmp(&right.value))
    });
    let mut identifier_bytes = Vec::with_capacity(identifiers.len() * 40);
    for item in &identifiers {
        let identifier_type = pool.intern(&item.identifier_type)?;
        let normalized = pool.intern(&item.normalized)?;
        let value = pool.intern(&item.value)?;
        let mut entry = [0u8; 40];
        put_u64(&mut entry[0..8], identifier_type.offset);
        put_u32(&mut entry[8..12], identifier_type.length);
        put_u64(&mut entry[12..20], normalized.offset);
        put_u32(&mut entry[20..24], normalized.length);
        put_u64(&mut entry[24..32], value.offset);
        put_u32(&mut entry[32..36], value.length);
        put_u32(&mut entry[36..40], item.record);
        identifier_bytes.extend_from_slice(&entry);
    }

    let metadata_values = vec![
        PACKAGE_SCHEMA_VERSION.to_string(),
        COMPILER_VERSION.to_string(),
        parsed.metadata.schema_version.clone(),
        parsed.metadata.component_id.clone(),
        parsed.metadata.catalog_id.clone(),
        parsed.metadata.catalog_version.clone(),
        parsed.metadata.catalog_checksum.clone(),
        parsed.metadata.catalog_mode.clone(),
        parsed.metadata.source_manifest_id.clone(),
        parsed.metadata.source_schema_version.clone(),
        parsed.metadata.normalization_profile.clone(),
        input_sha256.clone(),
    ];
    let metadata = encode_metadata(&metadata_values)?;
    let sections = vec![
        SectionData {
            kind: SECTION_METADATA,
            entry_size: 0,
            count: metadata_values.len() as u64,
            bytes: metadata,
        },
        SectionData {
            kind: SECTION_STRINGS,
            entry_size: 0,
            count: pool.refs.len() as u64,
            bytes: pool.data,
        },
        SectionData {
            kind: SECTION_RECORDS,
            entry_size: 32,
            count: parsed.records.len() as u64,
            bytes: records,
        },
        SectionData {
            kind: SECTION_NAMES,
            entry_size: 32,
            count: names.len() as u64,
            bytes: name_bytes,
        },
        SectionData {
            kind: SECTION_IDENTIFIERS,
            entry_size: 40,
            count: identifiers.len() as u64,
            bytes: identifier_bytes,
        },
    ];

    let directory_length = sections
        .len()
        .checked_mul(DIRECTORY_ENTRY_SIZE)
        .ok_or_else(|| "directory length overflow".to_string())?;
    let mut payload = vec![0u8; directory_length];
    let mut offset = HEADER_SIZE
        .checked_add(directory_length)
        .ok_or_else(|| "package offset overflow".to_string())?;
    for (index, section) in sections.iter().enumerate() {
        let base = index * DIRECTORY_ENTRY_SIZE;
        put_u32(&mut payload[base..base + 4], section.kind);
        put_u32(&mut payload[base + 4..base + 8], section.entry_size);
        put_u64(&mut payload[base + 8..base + 16], offset as u64);
        put_u64(
            &mut payload[base + 16..base + 24],
            section.bytes.len() as u64,
        );
        put_u64(&mut payload[base + 24..base + 32], section.count);
        offset = offset
            .checked_add(section.bytes.len())
            .ok_or_else(|| "package length overflow".to_string())?;
    }
    for section in sections {
        payload.extend_from_slice(&section.bytes);
    }

    let payload_digest = sha256::digest(&payload);
    let mut artifact = vec![0u8; HEADER_SIZE];
    artifact[0..8].copy_from_slice(MAGIC);
    put_u32(&mut artifact[8..12], FORMAT_VERSION);
    put_u32(&mut artifact[12..16], 5);
    put_u64(
        &mut artifact[16..24],
        u64::try_from(HEADER_SIZE + payload.len()).map_err(|_| "package too large")?,
    );
    put_u64(&mut artifact[24..32], HEADER_SIZE as u64);
    artifact[32..64].copy_from_slice(&payload_digest);
    artifact.extend_from_slice(&payload);
    let package_digest = sha256::digest(&artifact);

    let info = PackageInfo {
        schema_version: PACKAGE_SCHEMA_VERSION.to_string(),
        compiler_version: COMPILER_VERSION.to_string(),
        format_version: FORMAT_VERSION,
        component_id: parsed.metadata.component_id.clone(),
        catalog_id: parsed.metadata.catalog_id.clone(),
        catalog_version: parsed.metadata.catalog_version.clone(),
        catalog_checksum: parsed.metadata.catalog_checksum.clone(),
        catalog_mode: parsed.metadata.catalog_mode.clone(),
        source_manifest_id: parsed.metadata.source_manifest_id.clone(),
        source_schema_version: parsed.metadata.source_schema_version.clone(),
        normalization_profile: parsed.metadata.normalization_profile.clone(),
        input_sha256,
        payload_sha256: sha256::hex(&payload_digest),
        package_sha256: sha256::hex(&package_digest),
        package_length: artifact.len() as u64,
        record_count: parsed.records.len() as u64,
        name_count: names.len() as u64,
        identifier_count: identifiers.len() as u64,
    };
    Ok((artifact, info))
}

pub struct PackageView<'a> {
    data: &'a [u8],
    metadata: Vec<&'a str>,
    strings: Section,
    records: Section,
    names: Section,
    identifiers: Section,
    payload_sha256: String,
    package_sha256: String,
}

impl<'a> PackageView<'a> {
    pub fn open(data: &'a [u8]) -> Result<Self, String> {
        if data.len() < HEADER_SIZE || &data[0..8] != MAGIC {
            return Err("invalid package magic or truncated header".to_string());
        }
        if read_u32(&data[8..12]) != FORMAT_VERSION {
            return Err("unsupported package format version".to_string());
        }
        let section_count = read_u32(&data[12..16]) as usize;
        if section_count != 5 {
            return Err("unexpected section count".to_string());
        }
        let declared_length = read_u64(&data[16..24]) as usize;
        let directory_offset = read_u64(&data[24..32]) as usize;
        if declared_length != data.len() || directory_offset != HEADER_SIZE {
            return Err("package length or directory offset mismatch".to_string());
        }
        let directory_length = section_count
            .checked_mul(DIRECTORY_ENTRY_SIZE)
            .ok_or_else(|| "directory overflow".to_string())?;
        let directory_end = directory_offset
            .checked_add(directory_length)
            .ok_or_else(|| "directory overflow".to_string())?;
        if directory_end > data.len() {
            return Err("directory is out of bounds".to_string());
        }
        let payload_digest = sha256::digest(&data[directory_offset..]);
        if data[32..64] != payload_digest[..] {
            return Err("payload checksum mismatch".to_string());
        }

        let expected_kinds = [
            SECTION_METADATA,
            SECTION_STRINGS,
            SECTION_RECORDS,
            SECTION_NAMES,
            SECTION_IDENTIFIERS,
        ];
        let mut sections = Vec::with_capacity(section_count);
        let mut previous_end = directory_end;
        for (index, expected_kind) in expected_kinds.iter().enumerate() {
            let base = directory_offset + index * DIRECTORY_ENTRY_SIZE;
            let kind = read_u32(&data[base..base + 4]);
            let entry_size = read_u32(&data[base + 4..base + 8]);
            let offset = usize::try_from(read_u64(&data[base + 8..base + 16]))
                .map_err(|_| "section offset overflow")?;
            let length = usize::try_from(read_u64(&data[base + 16..base + 24]))
                .map_err(|_| "section length overflow")?;
            let count = usize::try_from(read_u64(&data[base + 24..base + 32]))
                .map_err(|_| "section count overflow")?;
            let end = offset
                .checked_add(length)
                .ok_or_else(|| "section range overflow".to_string())?;
            if kind != *expected_kind || offset != previous_end || end > data.len() {
                return Err("invalid, overlapping, or non-canonical section directory".to_string());
            }
            if entry_size > 0
                && count
                    .checked_mul(entry_size as usize)
                    .ok_or_else(|| "section size overflow".to_string())?
                    != length
            {
                return Err("fixed-size section length mismatch".to_string());
            }
            sections.push(Section {
                entry_size,
                offset,
                length,
                count,
            });
            previous_end = end;
        }
        if previous_end != data.len() {
            return Err("trailing package bytes".to_string());
        }
        let metadata = decode_metadata(section_bytes(data, sections[0]))?;
        if metadata.len() != METADATA_FIELD_COUNT
            || metadata[0] != PACKAGE_SCHEMA_VERSION
            || metadata[1] != COMPILER_VERSION
            || metadata[2] != input::SCHEMA_VERSION
            || metadata[10] != input::NORMALIZATION_PROFILE
        {
            return Err("unsupported package metadata contract".to_string());
        }
        if !metadata[3].starts_with("catalog_component_")
            || metadata[4].is_empty()
            || metadata[5].is_empty()
            || metadata[6].len() != 64
            || (metadata[7] != "official_list" && metadata[7] != "provider")
            || metadata[8].is_empty()
            || metadata[9].is_empty()
            || metadata[11].len() != 64
        {
            return Err("incomplete package metadata".to_string());
        }
        let view = Self {
            data,
            metadata,
            strings: sections[1],
            records: sections[2],
            names: sections[3],
            identifiers: sections[4],
            payload_sha256: sha256::hex(&payload_digest),
            package_sha256: sha256::hex(&sha256::digest(data)),
        };
        view.validate_entries()?;
        Ok(view)
    }

    pub fn info(&self) -> PackageInfo {
        PackageInfo {
            schema_version: self.metadata[0].to_string(),
            compiler_version: self.metadata[1].to_string(),
            format_version: FORMAT_VERSION,
            component_id: self.metadata[3].to_string(),
            catalog_id: self.metadata[4].to_string(),
            catalog_version: self.metadata[5].to_string(),
            catalog_checksum: self.metadata[6].to_string(),
            catalog_mode: self.metadata[7].to_string(),
            source_manifest_id: self.metadata[8].to_string(),
            source_schema_version: self.metadata[9].to_string(),
            normalization_profile: self.metadata[10].to_string(),
            input_sha256: self.metadata[11].to_string(),
            payload_sha256: self.payload_sha256.clone(),
            package_sha256: self.package_sha256.clone(),
            package_length: self.data.len() as u64,
            record_count: self.records.count as u64,
            name_count: self.names.count as u64,
            identifier_count: self.identifiers.count as u64,
        }
    }

    pub fn lookup_record(&self, record_id: &str) -> Result<Option<CandidateMatch>, String> {
        let mut low = 0usize;
        let mut high = self.records.count;
        while low < high {
            let middle = low + (high - low) / 2;
            let record = self.record(middle)?;
            match record.record_id.cmp(record_id) {
                std::cmp::Ordering::Less => low = middle + 1,
                std::cmp::Ordering::Greater => high = middle,
                std::cmp::Ordering::Equal => {
                    return Ok(Some(CandidateMatch {
                        record_id: record.record_id.to_string(),
                        entity_type: record.entity_type.to_string(),
                        primary_name: record.primary_name.to_string(),
                        match_kind: "record_id".to_string(),
                        matched_value: record.record_id.to_string(),
                        normalized_query: record_id.to_string(),
                    }))
                }
            }
        }
        Ok(None)
    }

    pub fn lookup_name(
        &self,
        query: &str,
        prefix: bool,
        limit: usize,
    ) -> Result<Vec<CandidateMatch>, String> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let normalized = normalize_name(query);
        if normalized.is_empty() {
            return Ok(Vec::new());
        }
        let mut low = 0usize;
        let mut high = self.names.count;
        while low < high {
            let middle = low + (high - low) / 2;
            let entry = self.name_entry(middle)?;
            if entry.normalized < normalized.as_str() {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        let mut output = Vec::new();
        let mut seen = BTreeSet::new();
        for index in low..self.names.count {
            let entry = self.name_entry(index)?;
            let matched = if prefix {
                entry.normalized.starts_with(&normalized)
            } else {
                entry.normalized == normalized
            };
            if !matched {
                if entry.normalized > normalized.as_str()
                    && (!prefix || !entry.normalized.starts_with(&normalized))
                {
                    break;
                }
                continue;
            }
            let record = self.record(entry.record_index)?;
            if !seen.insert(record.record_id.to_string()) {
                continue;
            }
            output.push(CandidateMatch {
                record_id: record.record_id.to_string(),
                entity_type: record.entity_type.to_string(),
                primary_name: record.primary_name.to_string(),
                match_kind: if entry.kind == 1 {
                    "primary_name".to_string()
                } else {
                    "alias".to_string()
                },
                matched_value: entry.value.to_string(),
                normalized_query: normalized.clone(),
            });
            if output.len() >= limit {
                break;
            }
        }
        Ok(output)
    }

    pub fn lookup_identifier(
        &self,
        identifier_type: &str,
        value: &str,
        limit: usize,
    ) -> Result<Vec<CandidateMatch>, String> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let identifier_type = normalize_type(identifier_type);
        let normalized = normalize_identifier(value);
        if identifier_type.is_empty() || normalized.is_empty() {
            return Ok(Vec::new());
        }
        let mut low = 0usize;
        let mut high = self.identifiers.count;
        while low < high {
            let middle = low + (high - low) / 2;
            let entry = self.identifier_entry(middle)?;
            if (entry.identifier_type, entry.normalized)
                < (identifier_type.as_str(), normalized.as_str())
            {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        let mut output = Vec::new();
        let mut seen = BTreeSet::new();
        for index in low..self.identifiers.count {
            let entry = self.identifier_entry(index)?;
            if entry.identifier_type != identifier_type || entry.normalized != normalized {
                break;
            }
            let record = self.record(entry.record_index)?;
            if !seen.insert(record.record_id.to_string()) {
                continue;
            }
            output.push(CandidateMatch {
                record_id: record.record_id.to_string(),
                entity_type: record.entity_type.to_string(),
                primary_name: record.primary_name.to_string(),
                match_kind: format!("exact_identifier:{}", identifier_type),
                matched_value: entry.value.to_string(),
                normalized_query: normalized.clone(),
            });
            if output.len() >= limit {
                break;
            }
        }
        Ok(output)
    }

    fn validate_entries(&self) -> Result<(), String> {
        let mut previous_record = "";
        for index in 0..self.records.count {
            let record = self.record(index)?;
            if record.record_id.is_empty()
                || record.primary_name.trim().is_empty()
                || (!previous_record.is_empty() && record.record_id <= previous_record)
            {
                return Err("record table is not canonical".to_string());
            }
            previous_record = record.record_id;
        }
        let mut previous_name: Option<(String, usize, u8, String)> = None;
        for index in 0..self.names.count {
            let entry = self.name_entry(index)?;
            if entry.normalized.is_empty()
                || entry.value.is_empty()
                || entry.record_index >= self.records.count
                || (entry.kind != 1 && entry.kind != 2)
            {
                return Err("invalid name index entry".to_string());
            }
            let key = (
                entry.normalized.to_string(),
                entry.record_index,
                entry.kind,
                entry.value.to_string(),
            );
            if previous_name.as_ref().is_some_and(|previous| &key <= previous) {
                return Err("name index is not sorted".to_string());
            }
            previous_name = Some(key);
        }
        let mut previous_identifier: Option<(String, String, usize, String)> = None;
        for index in 0..self.identifiers.count {
            let entry = self.identifier_entry(index)?;
            if entry.identifier_type.is_empty()
                || entry.normalized.is_empty()
                || entry.value.is_empty()
                || entry.record_index >= self.records.count
            {
                return Err("invalid identifier index entry".to_string());
            }
            let key = (
                entry.identifier_type.to_string(),
                entry.normalized.to_string(),
                entry.record_index,
                entry.value.to_string(),
            );
            if previous_identifier
                .as_ref()
                .is_some_and(|previous| &key <= previous)
            {
                return Err("identifier index is not sorted".to_string());
            }
            previous_identifier = Some(key);
        }
        Ok(())
    }

    fn record(&self, index: usize) -> Result<RecordView<'a>, String> {
        let entry = fixed_entry(self.data, self.records, index)?;
        let record_id = self.string(read_u64(&entry[0..8]), read_u32(&entry[8..12]))?;
        let primary_name = self.string(read_u64(&entry[12..20]), read_u32(&entry[20..24]))?;
        let entity_type = entity_type_name(entry[24])
            .ok_or_else(|| "record has unknown entity type".to_string())?;
        Ok(RecordView {
            record_id,
            primary_name,
            entity_type,
        })
    }

    fn name_entry(&self, index: usize) -> Result<NameView<'a>, String> {
        let entry = fixed_entry(self.data, self.names, index)?;
        Ok(NameView {
            normalized: self.string(read_u64(&entry[0..8]), read_u32(&entry[8..12]))?,
            value: self.string(read_u64(&entry[12..20]), read_u32(&entry[20..24]))?,
            record_index: read_u32(&entry[24..28]) as usize,
            kind: entry[28],
        })
    }

    fn identifier_entry(&self, index: usize) -> Result<IdentifierView<'a>, String> {
        let entry = fixed_entry(self.data, self.identifiers, index)?;
        Ok(IdentifierView {
            identifier_type: self.string(read_u64(&entry[0..8]), read_u32(&entry[8..12]))?,
            normalized: self.string(read_u64(&entry[12..20]), read_u32(&entry[20..24]))?,
            value: self.string(read_u64(&entry[24..32]), read_u32(&entry[32..36]))?,
            record_index: read_u32(&entry[36..40]) as usize,
        })
    }

    fn string(&self, offset: u64, length: u32) -> Result<&'a str, String> {
        let offset = usize::try_from(offset).map_err(|_| "string offset overflow")?;
        let length = length as usize;
        let start = self
            .strings
            .offset
            .checked_add(offset)
            .ok_or_else(|| "string offset overflow".to_string())?;
        let end = start
            .checked_add(length)
            .ok_or_else(|| "string range overflow".to_string())?;
        if offset > self.strings.length || end > self.strings.offset + self.strings.length {
            return Err("string reference is out of bounds".to_string());
        }
        std::str::from_utf8(&self.data[start..end])
            .map_err(|_| "string pool contains invalid UTF-8".to_string())
    }
}

#[derive(Clone, Copy)]
struct RecordView<'a> {
    record_id: &'a str,
    primary_name: &'a str,
    entity_type: &'static str,
}

#[derive(Clone, Copy)]
struct NameView<'a> {
    normalized: &'a str,
    value: &'a str,
    record_index: usize,
    kind: u8,
}

#[derive(Clone, Copy)]
struct IdentifierView<'a> {
    identifier_type: &'a str,
    normalized: &'a str,
    value: &'a str,
    record_index: usize,
}

pub fn normalize_name(value: &str) -> String {
    normalize_ascii(value, false, true)
}

pub fn normalize_identifier(value: &str) -> String {
    normalize_ascii(value, true, false)
}

pub fn normalize_type(value: &str) -> String {
    normalize_ascii(value, false, false)
}

fn normalize_ascii(value: &str, uppercase: bool, spaces: bool) -> String {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut pending_separator = false;
    for &byte in bytes {
        if byte >= 0x80 {
            if pending_separator && !output.is_empty() && spaces {
                output.push(b' ');
            }
            pending_separator = false;
            output.push(byte);
            continue;
        }
        if byte.is_ascii_alphanumeric() {
            if pending_separator && !output.is_empty() && spaces {
                output.push(b' ');
            }
            pending_separator = false;
            output.push(if uppercase {
                byte.to_ascii_uppercase()
            } else {
                byte.to_ascii_lowercase()
            });
        } else if spaces {
            pending_separator = true;
        }
    }
    while output.last() == Some(&b' ') {
        output.pop();
    }
    String::from_utf8(output).expect("normalization preserves UTF-8")
}

fn encode_metadata(values: &[String]) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    push_u32(&mut bytes, u32::try_from(values.len()).map_err(|_| "too many metadata fields")?);
    for value in values {
        push_u32(
            &mut bytes,
            u32::try_from(value.as_bytes().len()).map_err(|_| "metadata value too large")?,
        );
        bytes.extend_from_slice(value.as_bytes());
    }
    Ok(bytes)
}

fn decode_metadata(data: &[u8]) -> Result<Vec<&str>, String> {
    if data.len() < 4 {
        return Err("metadata section is truncated".to_string());
    }
    let count = read_u32(&data[0..4]) as usize;
    let mut position = 4usize;
    let mut output = Vec::with_capacity(count);
    for _ in 0..count {
        if position + 4 > data.len() {
            return Err("metadata length is truncated".to_string());
        }
        let length = read_u32(&data[position..position + 4]) as usize;
        position += 4;
        let end = position
            .checked_add(length)
            .ok_or_else(|| "metadata range overflow".to_string())?;
        if end > data.len() {
            return Err("metadata value is out of bounds".to_string());
        }
        output.push(
            std::str::from_utf8(&data[position..end])
                .map_err(|_| "metadata is not UTF-8".to_string())?,
        );
        position = end;
    }
    if position != data.len() {
        return Err("metadata has trailing bytes".to_string());
    }
    Ok(output)
}

fn fixed_entry(data: &[u8], section: Section, index: usize) -> Result<&[u8], String> {
    if index >= section.count || section.entry_size == 0 {
        return Err("fixed-entry index out of range".to_string());
    }
    let start = section
        .offset
        .checked_add(
            index
                .checked_mul(section.entry_size as usize)
                .ok_or_else(|| "entry offset overflow".to_string())?,
        )
        .ok_or_else(|| "entry offset overflow".to_string())?;
    let end = start
        .checked_add(section.entry_size as usize)
        .ok_or_else(|| "entry range overflow".to_string())?;
    if end > section.offset + section.length || end > data.len() {
        return Err("fixed-entry range is out of bounds".to_string());
    }
    Ok(&data[start..end])
}

fn section_bytes(data: &[u8], section: Section) -> &[u8] {
    &data[section.offset..section.offset + section.length]
}

fn entity_type_code(value: &str) -> Option<u8> {
    match value {
        "individual" => Some(1),
        "organization" => Some(2),
        "government_entity" => Some(3),
        "financial_institution" => Some(4),
        "vessel" => Some(5),
        "aircraft" => Some(6),
        "jurisdiction" => Some(7),
        _ => None,
    }
}

fn entity_type_name(value: u8) -> Option<&'static str> {
    match value {
        1 => Some("individual"),
        2 => Some("organization"),
        3 => Some("government_entity"),
        4 => Some("financial_institution"),
        5 => Some("vessel"),
        6 => Some("aircraft"),
        7 => Some("jurisdiction"),
        _ => None,
    }
}

fn put_u32(target: &mut [u8], value: u32) {
    target.copy_from_slice(&value.to_le_bytes());
}

fn put_u64(target: &mut [u8], value: u64) {
    target.copy_from_slice(&value.to_le_bytes());
}

fn push_u32(target: &mut Vec<u8>, value: u32) {
    target.extend_from_slice(&value.to_le_bytes());
}

fn read_u32(source: &[u8]) -> u32 {
    u32::from_le_bytes([source[0], source[1], source[2], source[3]])
}

fn read_u64(source: &[u8]) -> u64 {
    u64::from_le_bytes([
        source[0], source[1], source[2], source[3], source[4], source[5], source[6], source[7],
    ])
}

#[cfg(test)]
mod tests {
    use super::{normalize_identifier, normalize_name};

    #[test]
    fn normalization_profile_is_stable() {
        assert_eq!(normalize_name(" ACME---HOLDINGS, S.A. "), "acme holdings s a");
        assert_eq!(normalize_identifier(" P-12 34/56 "), "P123456");
        assert_eq!(normalize_name("МОСКВА Bank"), "МОСКВА bank");
    }
}
