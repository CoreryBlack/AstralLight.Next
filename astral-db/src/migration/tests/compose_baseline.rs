// The compose baseline fixture is a copy of the adopted identity migration's CREATE TABLE
// statements. These static checks pin that copy and the compose mounts so they cannot drift.

use std::path::Path;

const ADOPTED_IDENTITY_MIGRATION: &str =
    include_str!("../../../migrations/20240630000022_identity_ext.sql");
const IDENTITY_BASELINE_FIXTURE: &str =
    include_str!("../../../../Docs/sql/identity_ext_baseline.sql");
const COMPOSE_TEST: &str = include_str!("../../../../docker-compose.test.yml");

fn executable_lines(sql: &str) -> Vec<&str> {
    sql.lines()
        .map(str::trim_end)
        .filter(|line| !line.is_empty() && !line.starts_with("--"))
        .collect()
}

#[test]
fn identity_baseline_fixture_is_the_adopted_creator_head() {
    // Lines 1-30 of the adopted migration hold exactly its two CREATE TABLE statements;
    // the audit_log index tail that follows them must never enter the fixture.
    let head = ADOPTED_IDENTITY_MIGRATION
        .lines()
        .take(30)
        .collect::<Vec<_>>()
        .join("\n");
    let fixture = executable_lines(IDENTITY_BASELINE_FIXTURE);
    assert_eq!(fixture, executable_lines(&head));
    assert_eq!(
        fixture
            .iter()
            .filter(|line| line.starts_with("CREATE TABLE IF NOT EXISTS "))
            .count(),
        2
    );
    // The fixture header names audit_log on purpose, so only executable lines are checked.
    assert!(
        fixture.iter().all(|line| !line.contains("audit_log")),
        "the fixture must not index audit_log, which exists only after a later Rust migration"
    );
    assert!(
        fixture.iter().all(|line| !matches!(
            line.split_whitespace()
                .next()
                .map(str::to_ascii_uppercase)
                .as_deref(),
            Some("PREPARE" | "EXECUTE" | "SET" | "ALTER" | "DEALLOCATE")
        )),
        "the fixture holds CREATE statements only, with no dynamic or altering statement"
    );
}

/// The lines of one service's section under `services:`: from its key up to the next key
/// at the same two-space indentation, or up to the next top-level key.
fn service_section<'a>(compose: &'a str, service: &str) -> Vec<&'a str> {
    let key = format!("  {service}:");
    let mut section = Vec::new();
    let mut inside = false;
    for line in compose.lines() {
        if !inside {
            inside = line.trim_end() == key;
        } else if is_key_line(line, 2) {
            break;
        } else {
            section.push(line);
        }
    }
    section
}

/// The init mounts of the mysql service: the list items under its `volumes:` key, which sits
/// one level below the service key. Mount-like lines under any other key are not init mounts.
fn mysql_volume_entries(compose: &str) -> Vec<&str> {
    let mut entries = Vec::new();
    let mut inside = false;
    for line in service_section(compose, "mysql") {
        if !inside {
            inside = line.trim_end() == "    volumes:";
        } else if is_key_line(line, 4) {
            break;
        } else if line.trim_start().starts_with("- ") {
            entries.push(line.trim());
        }
    }
    entries
}

/// A mapping key indented at most `max_indent` spaces. Comments, blank lines and list items
/// are never keys.
fn is_key_line(line: &str, max_indent: usize) -> bool {
    let indent = line.len() - line.trim_start_matches(' ').len();
    indent <= max_indent
        && line
            .trim_start()
            .chars()
            .next()
            .is_some_and(char::is_alphanumeric)
}

const INIT_MOUNTS: [&str; 3] = [
    "- ./Docs/sql/full_schema_v4.sql:/docker-entrypoint-initdb.d/00-platform-v4.sql:ro",
    "- ./astral-db/migrations/20240630000012_user_mfa.sql:/docker-entrypoint-initdb.d/01-mfa-baseline.sql:ro",
    "- ./Docs/sql/identity_ext_baseline.sql:/docker-entrypoint-initdb.d/02-identity-ext-baseline.sql:ro",
];

#[test]
fn service_sections_stop_at_the_next_service_key() {
    // The mysql section is exactly the raw lines between its key and the rabbitmq key.
    let lines: Vec<&str> = COMPOSE_TEST.lines().collect();
    let start = lines
        .iter()
        .position(|line| line.trim_end() == "  mysql:")
        .unwrap();
    let end = lines
        .iter()
        .position(|line| line.trim_end() == "  rabbitmq:")
        .unwrap();
    assert_eq!(
        service_section(COMPOSE_TEST, "mysql"),
        lines[start + 1..end].to_vec()
    );
    let rabbitmq = service_section(COMPOSE_TEST, "rabbitmq");
    assert!(rabbitmq
        .iter()
        .any(|line| line.trim() == "image: rabbitmq:3-management"));
    assert!(!rabbitmq
        .iter()
        .any(|line| line.contains("/docker-entrypoint-initdb.d/")));
}

#[test]
fn service_section_stops_at_a_same_indent_key_or_a_top_level_key() {
    let compose = "services:\n  a:\n    image: x\n    # note\n\n      deep: 1\n  b:\n    image: y\nvolumes:\n  data: {}\n";
    assert_eq!(
        service_section(compose, "a"),
        ["    image: x", "    # note", "", "      deep: 1"]
    );
    assert_eq!(service_section(compose, "b"), ["    image: y"]);
}

#[test]
fn mysql_volume_entries_read_only_the_volumes_key() {
    assert_eq!(mysql_volume_entries(COMPOSE_TEST), INIT_MOUNTS);
    // The 00 mount moved under `environment:` is not an init mount, so the volumes list has two.
    const MOVED: &str = "\
services:
  mysql:
    image: mysql:8.0
    environment:
      - ./Docs/sql/full_schema_v4.sql:/docker-entrypoint-initdb.d/00-platform-v4.sql:ro
    volumes:
      - ./astral-db/migrations/20240630000012_user_mfa.sql:/docker-entrypoint-initdb.d/01-mfa-baseline.sql:ro
      - ./Docs/sql/identity_ext_baseline.sql:/docker-entrypoint-initdb.d/02-identity-ext-baseline.sql:ro
  rabbitmq:
    image: rabbitmq:3-management
";
    assert_eq!(mysql_volume_entries(MOVED), &INIT_MOUNTS[1..]);
}

#[test]
fn compose_init_mount_sources_exist_in_the_repository() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the astral-db crate sits in the repository root");
    for mount in INIT_MOUNTS {
        let source = mount
            .trim_start_matches("- ")
            .split(':')
            .next()
            .expect("a mount names its host source");
        assert!(
            root.join(source).is_file(),
            "init mount source {source} is missing from the repository"
        );
    }
}

#[test]
fn compose_mounts_the_identity_baseline_after_v4_and_mfa() {
    let mounts: Vec<&str> = mysql_volume_entries(COMPOSE_TEST)
        .into_iter()
        .filter(|line| line.contains("/docker-entrypoint-initdb.d/"))
        .collect();
    assert_eq!(mounts, INIT_MOUNTS);
    // Every init mount in the file belongs to the mysql service.
    let all = COMPOSE_TEST
        .lines()
        .filter(|line| line.contains("/docker-entrypoint-initdb.d/"))
        .count();
    assert_eq!(all, INIT_MOUNTS.len());
}
