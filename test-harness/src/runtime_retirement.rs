//! CURRENT V6 source/manifest contract guard for retired runtime surfaces.
//!
//! This is a source-level guard only: it parses Cargo TOML directly and walks
//! production Rust source roots without invoking Cargo or Git.

use regex::Regex;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use toml::Value as TomlValue;

const SELECTOR_LITERAL: &[u8] = b"ASTRAL_PROJECTION_EXECUTION_MODE";
const REDIS_COMPAT_LITERAL: &[u8] = b"ASTRAL_REDIS_PROJECTION_COMPAT";
const LEGACY_HYBRID_LITERAL: &[u8] = concat!("legacy-", "hybrid").as_bytes();

const RETIRED_FUNCTION_NAMES: &[&str] = &[
    "evaluate_realtime",
    "evaluate_snapshot",
    "evaluate_oracle",
    "evaluate_with_oracle",
    "realtime_evaluate",
    "evaluate_permission_rules",
    "try_match_rules_exact_first",
    "try_match_rules_single_pass",
    "arbitrate",
    "detect_conflict",
    "set_conflict_signal_sink",
    "emit_conflict_signal",
    "arbiter_routes",
    "consistency_monitor_routes",
    "parse_projection_execution_mode",
    "projection_execution_mode",
    "select_projection_execution_mode",
    "read_projection_execution_mode",
    "spawn_local_message_worker",
    "dispatch_local_message",
    "start_all_consumers",
];

const RETIRED_TYPE_NAMES: &[&str] = &[
    "GenericMessage",
    "DataScopeBypassGuard",
    "DecisionEvidence",
    "ConflictSignal",
    "ConflictSignalKind",
    "ArbitrationVerdict",
    "ArbitrationOutcome",
    "ArbiterService",
    "ArbiterStats",
    "ConsistencyViolation",
    "ConsistencyStats",
    "SnapshotConsistencyChecker",
    "RealtimeOracleRepo",
];

const OLD_L2_TYPE_NAMES: &[&str] = &[
    "PermissionRule",
    "SnapshotWinner",
    "RuleSetSnapshot",
    "RuleSetEntry",
    "RuleSetDependencyStatus",
];

struct SourcePatterns {
    retired_functions: Regex,
    retired_types: Regex,
    old_l2_types: Regex,
    mode_type: Regex,
    legacy_hybrid: Regex,
    selector_access: Regex,
    cache_compat_access: Regex,
    compat_selector_identifier: Regex,
    retired_cache_api: Regex,
}

fn source_patterns() -> &'static SourcePatterns {
    static PATTERNS: OnceLock<SourcePatterns> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        let functions = RETIRED_FUNCTION_NAMES.join("|");
        let retired_types = RETIRED_TYPE_NAMES.join("|");
        let old_l2_types = OLD_L2_TYPE_NAMES.join("|");
        SourcePatterns {
            retired_functions: Regex::new(&format!(
                r"\bfn\s+(?:{functions})\s*(?:<[^{{}};]*>)?\s*\("
            ))
            .expect("retired function regex"),
            retired_types: Regex::new(&format!(
                r"\b(?:struct|enum|type)\s+(?:{retired_types})\b"
            ))
            .expect("retired type regex"),
            old_l2_types: Regex::new(&format!(
                r"\b(?:struct|enum|type)\s+(?:{old_l2_types})\b"
            ))
            .expect("old L2 type regex"),
            mode_type: Regex::new(r"\bProjectionExecutionMode\b")
                .expect("execution mode regex"),
            legacy_hybrid: Regex::new(r"\bLegacyHybrid\b|__HYBRID__")
                .expect("legacy hybrid regex"),
            selector_access: Regex::new(
                r"(?:\benv\s*::\s*(?:var|var_os|set_var|remove_var)\s*\(\s*__RETIRE_MODE__|\b(?:env|option_env)!\s*\(\s*__RETIRE_MODE__)" ,
            )
            .expect("execution selector access regex"),
            cache_compat_access: Regex::new(
                r"(?:\benv\s*::\s*(?:var|var_os|set_var|remove_var)\s*\(\s*__RETIRE_REDIS__|\b(?:env|option_env)!\s*\(\s*__RETIRE_REDIS__)" ,
            )
            .expect("Redis compatibility access regex"),
            compat_selector_identifier: Regex::new(
                r"\bASTRAL_(?:REDIS_PROJECTION_COMPAT|PROJECTION_EXECUTION_MODE)\b",
            )
            .expect("retired selector identifier regex"),
            retired_cache_api: Regex::new(
                r"\bredis\s*::|\bredis_[A-Za-z0-9_]+\b|\b(?:Redis[A-Z][A-Za-z0-9_]*|[A-Za-z_][A-Za-z0-9_]*Redis[A-Z][A-Za-z0-9_]*)\b",
            )
            .expect("Redis runtime API regex"),
        }
    })
}

/// Check every Cargo manifest, retired crate surface, and production Rust source.
pub fn validate_runtime_retirement(workspace_root: &Path) -> Result<(), String> {
    let root = workspace_root
        .canonicalize()
        .map_err(|error| format!("resolve workspace root: {error}"))?;
    let manifests = find_named_files(&root, "Cargo.toml")?;
    if manifests.is_empty() {
        return Err("no Cargo.toml manifests found".into());
    }

    let mut violations = Vec::new();
    for manifest in &manifests {
        let text = match fs::read_to_string(manifest) {
            Ok(text) => text,
            Err(error) => {
                violations.push(format!(
                    "{}: read manifest: {error}",
                    display_path(&root, manifest)
                ));
                continue;
            }
        };
        let value: TomlValue = match toml::from_str(&text) {
            Ok(value) => value,
            Err(error) => {
                violations.push(format!(
                    "{}: invalid Cargo TOML: {error}",
                    display_path(&root, manifest)
                ));
                continue;
            }
        };
        inspect_manifest_values(&value, manifest, &root, &mut violations);
    }

    for path in retired_cache_surfaces(&root)? {
        violations.push(format!(
            "{}: retired astral-cache source/manifest/lock surface remains",
            display_path(&root, &path)
        ));
    }

    let source_violations = scan_production_sources(&root, &manifests)?;
    violations.extend(source_violations);
    violations.sort();
    violations.dedup();

    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations.join("\n"))
    }
}

fn inspect_manifest_values(
    value: &TomlValue,
    manifest: &Path,
    root: &Path,
    violations: &mut Vec<String>,
) {
    match value {
        TomlValue::Table(table) => {
            for (key, child) in table {
                if is_dependency_section(key) {
                    if let Some(dependencies) = child.as_table() {
                        for (alias, specification) in dependencies {
                            let package = specification
                                .get("package")
                                .and_then(TomlValue::as_str)
                                .unwrap_or(alias);
                            if contains_redis(package) || contains_redis(alias) {
                                violations.push(format!(
                                    "{}: Redis dependency `{alias}` (package `{package}`) is retired",
                                    display_path(root, manifest)
                                ));
                            }
                            inspect_dependency_features(
                                specification,
                                alias,
                                manifest,
                                root,
                                violations,
                            );
                        }
                    }
                }
                if key == "features" {
                    if let Some(features) = child.as_table() {
                        for (feature, contents) in features {
                            if contains_redis(feature) {
                                violations.push(format!(
                                    "{}: Redis feature `{feature}` is retired",
                                    display_path(root, manifest)
                                ));
                            }
                            inspect_feature_values(contents, feature, manifest, root, violations);
                        }
                    }
                }
                inspect_manifest_values(child, manifest, root, violations);
            }
        }
        TomlValue::Array(items) => {
            for item in items {
                inspect_manifest_values(item, manifest, root, violations);
            }
        }
        _ => {}
    }
}

fn inspect_dependency_features(
    specification: &TomlValue,
    alias: &str,
    manifest: &Path,
    root: &Path,
    violations: &mut Vec<String>,
) {
    let Some(features) = specification.get("features").and_then(TomlValue::as_array) else {
        return;
    };
    for feature in features.iter().filter_map(TomlValue::as_str) {
        if contains_redis(feature) {
            violations.push(format!(
                "{}: dependency `{alias}` propagates retired Redis feature `{feature}`",
                display_path(root, manifest)
            ));
        }
    }
}

fn inspect_feature_values(
    value: &TomlValue,
    feature: &str,
    manifest: &Path,
    root: &Path,
    violations: &mut Vec<String>,
) {
    match value {
        TomlValue::String(value) if contains_redis(value) => violations.push(format!(
            "{}: feature `{feature}` propagates retired Redis feature/dependency `{value}`",
            display_path(root, manifest)
        )),
        TomlValue::Array(items) => {
            for item in items {
                inspect_feature_values(item, feature, manifest, root, violations);
            }
        }
        _ => {}
    }
}

fn is_dependency_section(name: &str) -> bool {
    matches!(
        name,
        "dependencies" | "dev-dependencies" | "build-dependencies"
    )
}

fn contains_redis(value: &str) -> bool {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase()
        .contains("redis")
}

fn find_named_files(root: &Path, expected_name: &str) -> Result<Vec<PathBuf>, String> {
    let mut pending = vec![root.to_path_buf()];
    let mut found = Vec::new();
    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(&directory)
            .map_err(|error| format!("read {}: {error}", directory.display()))?;
        for entry in entries {
            let entry = entry.map_err(|error| format!("read directory entry: {error}"))?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|error| format!("inspect {}: {error}", path.display()))?;
            if file_type.is_dir() {
                if !skip_walk_directory(&entry.file_name().to_string_lossy()) {
                    pending.push(path);
                }
            } else if file_type.is_file() && entry.file_name() == expected_name {
                found.push(path);
            }
        }
    }
    found.sort();
    Ok(found)
}

fn retired_cache_surfaces(root: &Path) -> Result<Vec<PathBuf>, String> {
    let cache_root = root.join("astral-cache");
    if !cache_root.exists() {
        return Ok(Vec::new());
    }
    let mut pending = vec![cache_root];
    let mut found = Vec::new();
    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(&directory)
            .map_err(|error| format!("read {}: {error}", directory.display()))?;
        for entry in entries {
            let entry = entry.map_err(|error| format!("read directory entry: {error}"))?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|error| format!("inspect {}: {error}", path.display()))?;
            if file_type.is_dir() {
                if entry.file_name() != "target" {
                    pending.push(path);
                }
            } else if file_type.is_file() {
                let name = entry.file_name();
                if name == "Cargo.toml"
                    || name == "Cargo.lock"
                    || path.extension().is_some_and(|extension| extension == "rs")
                {
                    found.push(path);
                }
            }
        }
    }
    found.sort();
    Ok(found)
}

fn scan_production_sources(root: &Path, manifests: &[PathBuf]) -> Result<Vec<String>, String> {
    let files = production_source_files(manifests)?;
    let patterns = source_patterns();
    let mut violations = Vec::new();
    for path in files {
        let source = fs::read_to_string(&path)
            .map_err(|error| format!("read Rust source {}: {error}", path.display()))?;
        let source = without_cfg_test_items(&source);
        let code = mask_non_code(&source, true);
        for pattern in [
            (
                &patterns.retired_functions,
                "retired evaluator/oracle/arbiter/mode function",
            ),
            (
                &patterns.retired_types,
                "retired evaluator/oracle/arbiter type",
            ),
            (
                &patterns.mode_type,
                "retired projection execution mode selector",
            ),
            (&patterns.legacy_hybrid, "retired LegacyHybrid mode"),
            (
                &patterns.selector_access,
                "retired projection execution mode access",
            ),
            (
                &patterns.cache_compat_access,
                "retired Redis compatibility access",
            ),
            (
                &patterns.compat_selector_identifier,
                "retired runtime selector identifier",
            ),
            (&patterns.retired_cache_api, "retired Redis runtime API"),
        ] {
            if pattern.0.is_match(&code) {
                violations.push(format!(
                    "{}: {} remains in production Rust",
                    display_path(root, &path),
                    pattern.1
                ));
            }
        }
        if path.starts_with(root.join("policy-engine/src")) && patterns.old_l2_types.is_match(&code)
        {
            violations.push(format!(
                "{}: retired L2 evaluator type remains in production Rust",
                display_path(root, &path)
            ));
        }
    }
    Ok(violations)
}

fn production_source_files(manifests: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    let mut files = BTreeSet::new();
    for manifest in manifests {
        let crate_root = manifest
            .parent()
            .ok_or_else(|| format!("manifest has no parent: {}", manifest.display()))?;
        let source_root = crate_root.join("src");
        if source_root.is_dir() {
            walk_rust_sources(&source_root, &mut files)?;
        }
        let text = fs::read_to_string(manifest)
            .map_err(|error| format!("read {}: {error}", manifest.display()))?;
        let value: TomlValue = toml::from_str(&text)
            .map_err(|error| format!("parse {}: {error}", manifest.display()))?;
        let package = value.get("package");
        if let Some(build_script) = package
            .and_then(|package| package.get("build"))
            .and_then(TomlValue::as_str)
        {
            add_source_path(crate_root.join(build_script), &mut files);
        } else {
            add_source_path(crate_root.join("build.rs"), &mut files);
        }
        for target_name in ["lib", "bin"] {
            if let Some(target) = value.get(target_name) {
                add_target_source(crate_root, target, &mut files);
            }
        }
        if let Some(binaries) = value.get("bin").and_then(TomlValue::as_array) {
            for target in binaries {
                add_target_source(crate_root, target, &mut files);
            }
        }
    }
    Ok(files.into_iter().collect())
}

fn add_target_source(crate_root: &Path, target: &TomlValue, files: &mut BTreeSet<PathBuf>) {
    if let Some(path) = target.get("path").and_then(TomlValue::as_str) {
        add_source_path(crate_root.join(path), files);
    }
}

fn add_source_path(path: PathBuf, files: &mut BTreeSet<PathBuf>) {
    if path.is_file() && is_production_source_path(&path) {
        files.insert(path);
    }
}

fn walk_rust_sources(root: &Path, files: &mut BTreeSet<PathBuf>) -> Result<(), String> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(&directory)
            .map_err(|error| format!("read {}: {error}", directory.display()))?;
        for entry in entries {
            let entry = entry.map_err(|error| format!("read directory entry: {error}"))?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|error| format!("inspect {}: {error}", path.display()))?;
            if file_type.is_dir() {
                if !skip_source_directory(&entry.file_name().to_string_lossy()) {
                    pending.push(path);
                }
            } else if file_type.is_file() && is_production_source_path(&path) {
                files.insert(path);
            }
        }
    }
    Ok(())
}

fn is_production_source_path(path: &Path) -> bool {
    if path.extension().is_none_or(|extension| extension != "rs") {
        return false;
    }
    let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
        return false;
    };
    stem != "test" && stem != "tests" && !stem.ends_with("_tests")
}

fn skip_walk_directory(name: &str) -> bool {
    matches!(name, ".git" | "target" | "node_modules")
}

fn skip_source_directory(name: &str) -> bool {
    skip_walk_directory(name)
        || matches!(
            name,
            "test"
                | "tests"
                | "examples"
                | "example"
                | "bench"
                | "benches"
                | "migrations"
                | "archive"
        )
}

fn without_cfg_test_items(source: &str) -> String {
    static CFG_TEST: OnceLock<Regex> = OnceLock::new();
    let pattern = CFG_TEST.get_or_init(|| {
        Regex::new(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]").expect("cfg(test) attribute regex")
    });
    let visible = mask_non_code(source, false);
    let bytes = visible.as_bytes();
    let mut result = source.as_bytes().to_vec();
    let mut spans = pattern
        .find_iter(&visible)
        .map(|attribute| {
            let end = cfg_test_item_end(bytes, attribute.end());
            (attribute.start(), end)
        })
        .collect::<Vec<_>>();
    spans.sort_unstable_by_key(|(start, _)| std::cmp::Reverse(*start));
    for (start, end) in spans {
        for byte in &mut result[start..end] {
            if *byte != b'\n' && *byte != b'\r' {
                *byte = b' ';
            }
        }
    }
    String::from_utf8(result).expect("masking preserves UTF-8")
}

fn cfg_test_item_end(source: &[u8], mut index: usize) -> usize {
    while source.get(index).is_some_and(u8::is_ascii_whitespace) {
        index += 1;
    }
    let mut parentheses = 0usize;
    let mut brackets = 0usize;
    while let Some(byte) = source.get(index).copied() {
        match byte {
            b'(' => parentheses += 1,
            b')' => parentheses = parentheses.saturating_sub(1),
            b'[' => brackets += 1,
            b']' => brackets = brackets.saturating_sub(1),
            b'{' if parentheses == 0 && brackets == 0 => {
                let mut braces = 1usize;
                index += 1;
                while let Some(byte) = source.get(index).copied() {
                    match byte {
                        b'{' => braces += 1,
                        b'}' => {
                            braces -= 1;
                            if braces == 0 {
                                index += 1;
                                while source.get(index).is_some_and(u8::is_ascii_whitespace) {
                                    index += 1;
                                }
                                if source.get(index) == Some(&b';') {
                                    index += 1;
                                }
                                return index;
                            }
                        }
                        _ => {}
                    }
                    index += 1;
                }
                return source.len();
            }
            b';' if parentheses == 0 && brackets == 0 => return index + 1,
            _ => {}
        }
        index += 1;
    }
    source.len()
}

/// Blank comments and literals while preserving code; retain only the three
/// retired selector literals as opaque markers so actual environment reads can
/// be distinguished from the harness's intentional environment scrub list.
fn mask_non_code(source: &str, preserve_retired_literals: bool) -> String {
    let bytes = source.as_bytes();
    let mut result = bytes.to_vec();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes.get(index..index + 2) == Some(b"//") {
            let start = index;
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            blank_range(&mut result, start, index);
            continue;
        }
        if bytes.get(index..index + 2) == Some(b"/*") {
            let start = index;
            index += 2;
            let mut depth = 1usize;
            while index < bytes.len() && depth > 0 {
                if bytes.get(index..index + 2) == Some(b"/*") {
                    depth += 1;
                    index += 2;
                } else if bytes.get(index..index + 2) == Some(b"*/") {
                    depth -= 1;
                    index += 2;
                } else {
                    index += 1;
                }
            }
            blank_range(&mut result, start, index);
            continue;
        }
        if let Some((end, content_start, content_end)) = raw_string_bounds(bytes, index) {
            let content = &bytes[content_start..content_end];
            let marker = preserve_retired_literals.then(|| retired_literal_marker(content));
            if let Some(marker) = marker.flatten() {
                replace_with_marker(&mut result, index, end, marker);
            } else {
                blank_range(&mut result, index, end);
            }
            index = end;
            continue;
        }
        if bytes[index] == b'"' {
            let start = index;
            index += 1;
            while index < bytes.len() {
                if bytes[index] == b'\\' {
                    index = (index + 2).min(bytes.len());
                } else if bytes[index] == b'"' {
                    break;
                } else {
                    index += 1;
                }
            }
            let content_end = index;
            if index < bytes.len() {
                index += 1;
            }
            let marker = if preserve_retired_literals {
                retired_literal_marker(&bytes[start + 1..content_end])
            } else {
                None
            };
            if let Some(marker) = marker {
                replace_with_marker(&mut result, start, index, marker);
            } else {
                blank_range(&mut result, start, index);
            }
            continue;
        }
        if bytes[index] == b'\'' {
            if let Some(end) = character_literal_end(bytes, index) {
                blank_range(&mut result, index, end);
                index = end;
                continue;
            }
        }
        index += 1;
    }
    String::from_utf8(result).expect("masking preserves UTF-8")
}

fn raw_string_bounds(bytes: &[u8], index: usize) -> Option<(usize, usize, usize)> {
    let raw_start = if bytes.get(index) == Some(&b'r') {
        index
    } else if matches!(bytes.get(index), Some(b'b' | b'c')) && bytes.get(index + 1) == Some(&b'r') {
        index + 1
    } else {
        return None;
    };
    let mut quote = raw_start + 1;
    while bytes.get(quote) == Some(&b'#') {
        quote += 1;
    }
    if bytes.get(quote) != Some(&b'"') {
        return None;
    }
    let hashes = quote - raw_start - 1;
    let content_start = quote + 1;
    let mut cursor = content_start;
    while cursor < bytes.len() {
        if bytes[cursor] == b'"'
            && bytes
                .get(cursor + 1..cursor + 1 + hashes)
                .is_some_and(|suffix| suffix.iter().all(|byte| *byte == b'#'))
        {
            return Some((cursor + 1 + hashes, content_start, cursor));
        }
        cursor += 1;
    }
    Some((bytes.len(), content_start, bytes.len()))
}

fn character_literal_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut index = start + 1;
    if bytes.get(index) == Some(&b'\\') {
        index += 1;
        if bytes.get(index) == Some(&b'u') && bytes.get(index + 1) == Some(&b'{') {
            index += 2;
            while bytes.get(index).is_some_and(|byte| *byte != b'}') {
                index += 1;
            }
            if bytes.get(index) != Some(&b'}') {
                return None;
            }
            index += 1;
        } else {
            index += 1;
        }
    } else {
        let character = std::str::from_utf8(bytes.get(index..)?)
            .ok()?
            .chars()
            .next()?;
        index += character.len_utf8();
    }
    (bytes.get(index) == Some(&b'\'')).then_some(index + 1)
}

fn retired_literal_marker(content: &[u8]) -> Option<&'static [u8]> {
    match content {
        SELECTOR_LITERAL => Some(b"__RETIRE_MODE__"),
        REDIS_COMPAT_LITERAL => Some(b"__RETIRE_REDIS__"),
        LEGACY_HYBRID_LITERAL => Some(b"__HYBRID__"),
        _ => None,
    }
}

fn blank_range(bytes: &mut [u8], start: usize, end: usize) {
    for byte in &mut bytes[start..end] {
        if *byte != b'\n' && *byte != b'\r' {
            *byte = b' ';
        }
    }
}

fn replace_with_marker(bytes: &mut [u8], start: usize, end: usize, marker: &[u8]) {
    blank_range(bytes, start, end);
    let marker_end = start + marker.len().min(end - start);
    bytes[start..marker_end].copy_from_slice(&marker[..marker_end - start]);
}

fn display_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        // 证据文本统一正斜杠，findings 跨平台可比。
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempWorkspace(PathBuf);

    impl TempWorkspace {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("runtime-retirement-{}", uuid::Uuid::new_v4()));
            fs::create_dir_all(path.join("src")).expect("create temporary source root");
            fs::write(
                path.join("Cargo.toml"),
                "[package]\nname = \"retirement-probe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .expect("write temporary manifest");
            Self(path)
        }
    }

    impl Drop for TempWorkspace {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn current_runtime_has_no_retired_dependencies_or_execution_paths() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root");
        validate_runtime_retirement(root).expect("current runtime retirement contract");
    }

    #[test]
    fn discovers_retired_definition_in_a_split_production_file() {
        let workspace = TempWorkspace::new();
        let split = workspace.0.join("src/split/evaluator.rs");
        fs::create_dir_all(split.parent().expect("split parent")).expect("create split source");
        fs::write(workspace.0.join("src/lib.rs"), "mod split;\n").expect("write crate root");
        fs::write(&split, "pub async fn evaluate_realtime() {}\n").expect("write split source");

        let findings = scan_production_sources(&workspace.0, &[workspace.0.join("Cargo.toml")])
            .expect("scan split production source");
        assert!(findings.iter().any(|finding| {
            finding.contains("src/split/evaluator.rs") && finding.contains("retired evaluator")
        }));
    }

    #[test]
    fn ignores_a_retired_api_literal_inside_cfg_test() {
        let workspace = TempWorkspace::new();
        fs::write(
            workspace.0.join("src/lib.rs"),
            "#[cfg(test)]\nmod tests {\n    const EXAMPLE: &str = \"pub async fn evaluate_realtime(\";\n}\n",
        )
        .expect("write test-only literal");

        let findings = scan_production_sources(&workspace.0, &[workspace.0.join("Cargo.toml")])
            .expect("scan test-only source");
        assert!(
            findings.is_empty(),
            "test-only literal was reported: {findings:?}"
        );
    }
}
