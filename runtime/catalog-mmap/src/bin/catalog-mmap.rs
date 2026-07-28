use openwatchlist_catalog_mmap::{compile, run_worker, CandidateMatch, MappedPackage, PackageInfo};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

fn main() {
    if let Err(error) = run() {
        eprintln!("catalog-mmap: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let command = args.next().ok_or_else(usage)?;
    let options = parse_options(args.collect())?;
    match command.as_str() {
        "compile" => {
            let input = required_path(&options, "input")?;
            let output = required_path(&options, "output")?;
            let input_bytes = fs::read(&input).map_err(|error| format!("read input: {error}"))?;
            let (artifact, info) = compile(&input_bytes)?;
            write_atomic(&output, &artifact)?;
            println!("{}", info_json(&info, None));
        }
        "verify" | "inspect" => {
            let package = required_path(&options, "package")?;
            let mapped = MappedPackage::open(&package)?;
            let info = mapped.view()?.info();
            println!(
                "{}",
                info_json(&info, if command == "verify" { Some(true) } else { None })
            );
        }
        "lookup-record" => {
            let package = required_path(&options, "package")?;
            let record_id = required(&options, "record-id")?;
            let mapped = MappedPackage::open(&package)?;
            let result = mapped.view()?.lookup_record(record_id)?;
            let values = result.into_iter().collect::<Vec<_>>();
            println!("{}", matches_json("record_id", record_id, &values));
        }
        "lookup-name" => {
            let package = required_path(&options, "package")?;
            let query = required(&options, "query")?;
            let prefix = options.contains_key("prefix");
            let limit = parse_limit(&options)?;
            let mapped = MappedPackage::open(&package)?;
            let values = mapped.view()?.lookup_name(query, prefix, limit)?;
            println!(
                "{}",
                matches_json(if prefix { "name_prefix" } else { "name_exact" }, query, &values)
            );
        }
        "lookup-identifier" => {
            let package = required_path(&options, "package")?;
            let identifier_type = required(&options, "type")?;
            let value = required(&options, "value")?;
            let limit = parse_limit(&options)?;
            let mapped = MappedPackage::open(&package)?;
            let values = mapped
                .view()?
                .lookup_identifier(identifier_type, value, limit)?;
            println!("{}", matches_json("exact_identifier", value, &values));
        }
        "worker" => {
            let package = required_path(&options, "package")?;
            run_worker(&package)?;
        }
        "benchmark-name" => {
            let package = required_path(&options, "package")?;
            let query = required(&options, "query")?;
            let prefix = options.contains_key("prefix");
            let iterations = parse_iterations(&options)?;
            let mapped = MappedPackage::open(&package)?;
            let view = mapped.view()?;
            let started = Instant::now();
            let mut total_matches = 0usize;
            for _ in 0..iterations {
                total_matches += view.lookup_name(query, prefix, 20)?.len();
            }
            let elapsed = started.elapsed();
            let elapsed_ns = elapsed.as_nanos();
            let lookups_per_second = if elapsed_ns == 0 {
                0.0
            } else {
                iterations as f64 * 1_000_000_000.0 / elapsed_ns as f64
            };
            println!(
                "{{\"query\":\"{}\",\"prefix\":{},\"iterations\":{},\"total_matches\":{},\"elapsed_ns\":{},\"lookups_per_second\":{:.2}}}",
                escape(query),
                prefix,
                iterations,
                total_matches,
                elapsed_ns,
                lookups_per_second
            );
        }
        _ => return Err(usage()),
    }
    Ok(())
}

fn parse_options(values: Vec<String>) -> Result<BTreeMap<String, Option<String>>, String> {
    let mut options = BTreeMap::new();
    let mut index = 0usize;
    while index < values.len() {
        let raw = &values[index];
        if !raw.starts_with("--") {
            return Err(format!("unexpected positional argument {raw:?}"));
        }
        let key = raw.trim_start_matches("--").to_string();
        if key == "prefix" {
            options.insert(key, None);
            index += 1;
            continue;
        }
        index += 1;
        let value = values
            .get(index)
            .ok_or_else(|| format!("--{key} requires a value"))?
            .clone();
        if value.starts_with("--") {
            return Err(format!("--{key} requires a value"));
        }
        if options.insert(key.clone(), Some(value)).is_some() {
            return Err(format!("duplicate --{key}"));
        }
        index += 1;
    }
    Ok(options)
}

fn required<'a>(options: &'a BTreeMap<String, Option<String>>, key: &str) -> Result<&'a str, String> {
    options
        .get(key)
        .and_then(|value| value.as_deref())
        .ok_or_else(|| format!("--{key} is required"))
}

fn required_path(options: &BTreeMap<String, Option<String>>, key: &str) -> Result<PathBuf, String> {
    Ok(PathBuf::from(required(options, key)?))
}

fn parse_limit(options: &BTreeMap<String, Option<String>>) -> Result<usize, String> {
    let value = options
        .get("limit")
        .and_then(|value| value.as_deref())
        .unwrap_or("20");
    let limit = value
        .parse::<usize>()
        .map_err(|_| "--limit must be a positive integer".to_string())?;
    if limit == 0 || limit > 10_000 {
        return Err("--limit must be between 1 and 10000".to_string());
    }
    Ok(limit)
}

fn parse_iterations(options: &BTreeMap<String, Option<String>>) -> Result<usize, String> {
    let value = options
        .get("iterations")
        .and_then(|value| value.as_deref())
        .unwrap_or("10000");
    let iterations = value
        .parse::<usize>()
        .map_err(|_| "--iterations must be a positive integer".to_string())?;
    if iterations == 0 || iterations > 100_000_000 {
        return Err("--iterations must be between 1 and 100000000".to_string());
    }
    Ok(iterations)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(directory).map_err(|error| format!("create output directory: {error}"))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "output filename is invalid UTF-8".to_string())?;
    let temporary = directory.join(format!(".{file_name}.tmp-{}", std::process::id()));
    let result = (|| {
        let mut file = fs::File::create(&temporary)
            .map_err(|error| format!("create temporary package: {error}"))?;
        file.write_all(bytes)
            .map_err(|error| format!("write temporary package: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("sync temporary package: {error}"))?;
        drop(file);
        fs::rename(&temporary, path).map_err(|error| format!("activate package file: {error}"))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn info_json(info: &PackageInfo, valid: Option<bool>) -> String {
    let mut fields = Vec::new();
    if let Some(value) = valid {
        fields.push(format!("\"valid\":{value}"));
    }
    fields.extend([
        pair("schema_version", &info.schema_version),
        pair("compiler_version", &info.compiler_version),
        format!("\"format_version\":{}", info.format_version),
        pair("component_id", &info.component_id),
        pair("catalog_id", &info.catalog_id),
        pair("catalog_version", &info.catalog_version),
        pair("catalog_checksum", &info.catalog_checksum),
        pair("catalog_mode", &info.catalog_mode),
        pair("source_manifest_id", &info.source_manifest_id),
        pair("source_schema_version", &info.source_schema_version),
        pair("normalization_profile", &info.normalization_profile),
        pair("input_sha256", &info.input_sha256),
        pair("payload_sha256", &info.payload_sha256),
        pair("package_sha256", &info.package_sha256),
        format!("\"package_length\":{}", info.package_length),
        format!("\"record_count\":{}", info.record_count),
        format!("\"name_count\":{}", info.name_count),
        format!("\"identifier_count\":{}", info.identifier_count),
    ]);
    format!("{{{}}}", fields.join(","))
}

fn matches_json(kind: &str, query: &str, matches: &[CandidateMatch]) -> String {
    let values = matches.iter().map(match_json).collect::<Vec<_>>().join(",");
    format!(
        "{{\"query_kind\":\"{}\",\"query\":\"{}\",\"match_count\":{},\"matches\":[{}]}}",
        escape(kind),
        escape(query),
        matches.len(),
        values
    )
}

fn match_json(value: &CandidateMatch) -> String {
    format!(
        "{{\"record_id\":\"{}\",\"entity_type\":\"{}\",\"primary_name\":\"{}\",\"match_kind\":\"{}\",\"matched_value\":\"{}\",\"normalized_query\":\"{}\"}}",
        escape(&value.record_id),
        escape(&value.entity_type),
        escape(&value.primary_name),
        escape(&value.match_kind),
        escape(&value.matched_value),
        escape(&value.normalized_query)
    )
}

fn pair(key: &str, value: &str) -> String {
    format!("\"{}\":\"{}\"", escape(key), escape(value))
}

fn escape(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 8);
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character < '\u{20}' => {
                output.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => output.push(character),
        }
    }
    output
}

fn usage() -> String {
    "usage: catalog-mmap <compile|verify|inspect|lookup-record|lookup-name|lookup-identifier|worker|benchmark-name> [--input FILE --output FILE | --package FILE]".to_string()
}
