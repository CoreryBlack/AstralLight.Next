use super::{
    env, json, read_manifest, run_selected_with_runtime, select_suites, snapshot_hash, str_field,
    string_array, suite_id, Manifest, Options, SelectedRuntime, TomlValue, Value,
};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

#[path = "../../../tests-suite/src/paper_mysql_scope.rs"]
pub(super) mod mysql_scope;

pub(super) fn is_mysql_suite(suite: &TomlValue) -> bool {
    suite.get("paper_lane").and_then(TomlValue::as_str) == Some("mysql")
}

static CANCELLED: AtomicBool = AtomicBool::new(false);

pub(super) fn cancelled(suite: &TomlValue) -> bool {
    (is_paper_suite(suite) || super::darkstar::is_suite(suite)) && CANCELLED.load(Ordering::Relaxed)
}

#[cfg(unix)]
pub(super) struct InterruptGuard(Vec<(libc::c_int, libc::sigaction)>);

#[cfg(unix)]
impl InterruptGuard {
    pub(super) fn install() -> Result<Self, String> {
        extern "C" fn cancel(_: libc::c_int) {
            CANCELLED.store(true, Ordering::Relaxed);
        }
        CANCELLED.store(false, Ordering::Relaxed);
        let mut guard = Self(Vec::new());
        for signal in [libc::SIGINT, libc::SIGTERM] {
            // The handler only sets a lock-free atomic. Process cleanup runs in the runner.
            unsafe {
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = cancel as *const () as usize;
                action.sa_flags = libc::SA_RESTART;
                libc::sigemptyset(&mut action.sa_mask);
                let mut previous = std::mem::MaybeUninit::uninit();
                if libc::sigaction(signal, &action, previous.as_mut_ptr()) != 0 {
                    return Err(format!(
                        "install paper interrupt handler: {}",
                        std::io::Error::last_os_error()
                    ));
                }
                guard.0.push((signal, previous.assume_init()));
            }
        }
        Ok(guard)
    }
}

#[cfg(unix)]
impl Drop for InterruptGuard {
    fn drop(&mut self) {
        for (signal, previous) in self.0.drain(..).rev() {
            unsafe { libc::sigaction(signal, &previous, std::ptr::null_mut()) };
        }
        CANCELLED.store(false, Ordering::Relaxed);
    }
}

pub(super) struct Scratch(PathBuf);

impl Scratch {
    pub(super) fn new(phase: &Path, id: &str) -> Result<Self, String> {
        let path = phase.join(format!("{id}.scratch"));
        #[cfg(unix)]
        let created = {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().mode(0o700).create(&path)
        };
        #[cfg(not(unix))]
        let created = fs::create_dir(&path);
        created.map_err(|error| format!("create run-scoped paper fixture directory: {error}"))?;
        Ok(Self(path))
    }

    pub(super) fn bind(&self, env: &mut BTreeMap<OsString, OsString>) {
        for key in ["TMPDIR", "TEMP", "TMP"] {
            env.insert(key.into(), self.0.as_os_str().to_owned());
        }
    }

    pub(super) fn path(&self) -> &Path {
        &self.0
    }

    pub(super) fn clean(&self) -> Result<(), String> {
        fs::remove_dir_all(&self.0)
            .map_err(|error| format!("remove owned paper fixture directory: {error}"))
    }
}

pub const PAPER_USAGE: &str = "DarkStar paper campaign\n\
Usage: bash scripts/run-paper-tests.sh [--list] [--track both|usenix|cose] \
[--controls] [--heavy] [--performance] [--loopback] [--all-local] [--repair-full] \
[--artifact-root PATH] [--run-id ID]\n\
       bash scripts/run-paper-tests.sh --mysql --run-id ID [--list] [--artifact-root PATH]\n\
Default: both papers' offline correctness suites. --all-local adds current-source controls, \
heavy, performance and loopback; --repair-full selects the unpublished large repair model.\n\
--mysql selects only the USENIX run-scoped MySQL fixture; requires prior approval and a dedicated, \
pre-migrated loopback schema. No container, migration, schema deletion or production deployment.\n\
Builds require an installed Rust toolchain, Git and cached locked Cargo dependencies.\n";

#[derive(Default)]
struct PaperOptions {
    common: Options,
    track: Track,
    list: bool,
    controls: bool,
    heavy: bool,
    performance: bool,
    loopback: bool,
    repair: bool,
    mysql: bool,
    // Set only by all_darkstar_suites; never a --paper CLI option.
    all_lanes: bool,
    explicit_run: bool,
}

#[derive(Default)]
enum Track {
    #[default]
    Both,
    Usenix,
    Cose,
}

impl Track {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Both => "both",
            Self::Usenix => "usenix",
            Self::Cose => "cose",
        }
    }

    fn includes(&self, track: &str) -> bool {
        matches!(self, Self::Both) || self.as_str() == track || track == "both"
    }
}

impl PaperOptions {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut options = Self::default();
        options.common.run_id = options
            .common
            .run_id
            .replace("test-campaign-", "darkstar-paper-");
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            let mut value = || {
                args.next()
                    .ok_or_else(|| format!("missing value for {arg}"))
            };
            match arg.as_str() {
                "--list" => options.list = true,
                "--track" => {
                    options.track = match value()?.as_str() {
                        "both" => Track::Both,
                        "usenix" => Track::Usenix,
                        "cose" => Track::Cose,
                        _ => return Err("paper track must be both, usenix, or cose".into()),
                    }
                }
                "--controls" => options.controls = true,
                "--heavy" => options.heavy = true,
                "--performance" => options.performance = true,
                "--loopback" => options.loopback = true,
                "--all-local" => {
                    options.controls = true;
                    options.heavy = true;
                    options.performance = true;
                    options.loopback = true;
                }
                "--repair-full" => options.repair = true,
                "--mysql" => options.mysql = true,
                "--run-id" => {
                    options.common.run_id = value()?.clone();
                    options.explicit_run = true;
                }
                "--artifact-root" => options.common.artifact_root = value()?.into(),
                _ => return Err(format!("unknown paper option: {arg}")),
            }
        }
        if options.repair && matches!(options.track, Track::Usenix) {
            return Err("--repair-full requires the cose or both track".into());
        }
        if options.mysql {
            if matches!(options.track, Track::Cose)
                || options.controls
                || options.heavy
                || options.performance
                || options.loopback
                || options.repair
            {
                return Err(
                    "--mysql is a separate USENIX-only run, not a local-lane modifier".into(),
                );
            }
            if !options.list && !options.explicit_run {
                return Err("--mysql requires an explicit --run-id".into());
            }
            if options.explicit_run {
                mysql_scope::schema_name(&options.common.run_id)?;
            }
            options.track = Track::Usenix;
        }
        Ok(options)
    }

    fn includes_lane(&self, lane: &str) -> bool {
        if self.all_lanes {
            return matches!(
                lane,
                "core" | "controls" | "heavy" | "performance" | "loopback" | "repair" | "mysql"
            );
        }
        if self.mysql {
            return lane == "mysql";
        }
        match lane {
            "core" => true,
            "controls" => self.controls,
            "heavy" => self.heavy,
            "performance" => self.performance,
            "loopback" => self.loopback,
            "repair" => self.repair,
            _ => false,
        }
    }

    fn plan(&self, manifest: &Manifest) -> Result<(Vec<String>, Value), String> {
        let mut ids = Vec::new();
        let mut items = Vec::new();
        for suite in manifest
            .suites
            .iter()
            .filter(|suite| suite.get("paper_lane").is_some())
        {
            validate_suite(suite)?;
            let id = suite_id(suite);
            let track = str_field(suite, "paper_track")?;
            let lane = str_field(suite, "paper_lane")?;
            let selected = self.track.includes(track) && self.includes_lane(lane);
            if selected {
                ids.push(id.clone());
            }
            items.push(
                json!({"id":id,"track":track,"lane":lane,"selected":selected,
                "boundary":suite.get("boundary"),"argv":suite.get("argv"),
                "selection_status":if selected { "SELECTED" } else { "SKIP" }}),
            );
        }
        if ids.is_empty() {
            return Err("no runnable paper suites for this selection".into());
        }
        let unavailable = json!([
            {"track":"usenix","id":"historical-http-ab","status":"BLOCKED","reason":"historical build and round inputs missing; local tests measure only the current arm"},
            {"track":"both","id":"historical-production-mutation-scores","status":"SKIP","reason":"archived historical results; runner neither edits production guards nor re-scores historical snapshots"},
            {"track":"cose","id":"historical-owner-timings","status":"BLOCKED","reason":"original raw output and environment were not retained; local timings are new observations"},
            {"track":"usenix","id":"deployed-object-binding-and-db-authority-baseline","status":"BLOCKED","reason":"no deployed ordinary object-bearing route or equivalent synchronous DB authority benchmark in this checkout"},
            {"track":"both","id":"deployment-and-physical-crashes","status":"BLOCKED","reason":"no paper lane proves production fact provenance, all deployed writers, MySQL apply, or physical power loss"}
        ]);
        Ok((
            ids,
            json!({"track":self.track.as_str(),"items":items,"unavailable":unavailable,
            "result_scope":"selected suites on the current source snapshot, not historical reproduction or production acceptance"}),
        ))
    }
}

/// DarkStar campaign selection: every registered paper suite, equivalent to
/// --all-local --repair-full plus the dedicated MySQL fixture, which is always
/// included; the darkstar runner blocks or skips it explicitly when its
/// dedicated approval is missing. The missing historical boundaries stay in the
/// returned plan under `unavailable`.
pub(super) fn all_darkstar_suites(manifest: &Manifest) -> Result<(Vec<String>, Value), String> {
    let options = PaperOptions {
        controls: true,
        heavy: true,
        performance: true,
        loopback: true,
        repair: true,
        mysql: true,
        all_lanes: true,
        ..PaperOptions::default()
    };
    options.plan(manifest)
}

fn validate_suite(suite: &TomlValue) -> Result<(), String> {
    let id = suite_id(suite);
    let track = str_field(suite, "paper_track")?;
    let lane = str_field(suite, "paper_lane")?;
    let argv = string_array(suite, "argv")?;
    let services = string_array(suite, "test_services")?;
    let profile = super::suite_profile(suite);
    let target_ok = if is_mysql_suite(suite) {
        id == "paper-usenix-mysql"
            && track == "usenix"
            && profile == "native-single-node"
            && services == ["mysql"]
            && str_field(suite, "scope")? == "integration"
            && argv.iter().map(String::as_str).eq([
                "cargo",
                "test",
                "--locked",
                "--offline",
                "-p",
                "astral-single-node",
                "--test",
                "memory_v1_service_process",
                "--",
                "--ignored",
                "--exact",
                "paper_mysql::cold_snapshot_and_warm_governance",
                "--nocapture",
                "--test-threads=1",
            ])
            && suite.get("expected_tests").and_then(TomlValue::as_integer) == Some(1)
    } else {
        matches!(
            lane,
            "core" | "controls" | "heavy" | "performance" | "loopback" | "repair"
        ) && matches!(
            profile.as_str(),
            "native-kernel" | "offline-validation" | "performance-kernel"
        ) && services.is_empty()
    };
    if !matches!(track, "both" | "usenix" | "cose")
        || !target_ok
        || !id.starts_with("paper-")
        || suite.get("selection_policy").and_then(TomlValue::as_str) != Some("explicit-suite")
        || str_field(suite, "acceptance")? != "rust"
        || suite
            .get("expected_tests")
            .and_then(TomlValue::as_integer)
            .is_none_or(|count| count < 1)
        || !argv
            .iter()
            .take(4)
            .map(String::as_str)
            .eq(["cargo", "test", "--locked", "--offline"])
        || argv.iter().any(|arg| {
            matches!(
                arg.as_str(),
                "--workspace" | "--manifest-path" | "--all-features"
            )
        })
    {
        return Err(format!("invalid offline paper suite contract: {id}"));
    }
    if let Some(mode) = suite.get("paper_fixture") {
        if !matches!(
            (lane, mode.as_str()),
            ("performance", Some("evaluator-load"))
                | ("loopback", Some("http-default" | "http-expanded"))
        ) {
            return Err(format!("invalid paper fixture setting: {id}"));
        }
    }
    if suite.get("paper_measurement").is_some()
        && (!matches!(lane, "performance" | "loopback")
            || str_field(suite, "paper_measurement")?.is_empty()
            || suite
                .get("paper_rows")
                .and_then(TomlValue::as_integer)
                .is_none_or(|count| count < 1))
    {
        return Err(format!("invalid paper measurement contract: {id}"));
    }
    Ok(())
}

pub(super) fn is_paper_suite(suite: &TomlValue) -> bool {
    suite.get("paper_lane").is_some()
}

/// Allowlisted toolchain environment plus the offline-build constants shared by
/// paper and darkstar suite children. Ambient DB URLs, credentials, integration
/// flags, compiler wrappers and the fixture child-process switches are never
/// forwarded.
pub(super) fn clean_environment(original: &[(OsString, OsString)]) -> BTreeMap<OsString, OsString> {
    let mut result = original
        .iter()
        .filter(|(name, _)| {
            matches!(
                name.to_str(),
                Some(
                    "PATH"
                        | "HOME"
                        | "USERPROFILE"
                        | "SystemRoot"
                        | "SYSTEMROOT"
                        | "WINDIR"
                        | "COMSPEC"
                        | "PATHEXT"
                        | "CARGO_HOME"
                        | "RUSTUP_HOME"
                        | "CARGO_TARGET_DIR"
                        | "CARGO_BUILD_JOBS"
                        | "CARGO_INCREMENTAL"
                )
            )
        })
        .cloned()
        .collect::<BTreeMap<_, _>>();
    result.insert("CARGO_NET_OFFLINE".into(), "true".into());
    result.insert("CARGO_TERM_COLOR".into(), "never".into());
    result.insert("RUSTUP_AUTO_INSTALL".into(), "0".into());
    result.insert("ASTRAL_MESSAGE_TRANSPORT".into(), "local".into());
    result
}

pub(super) fn environment(
    suite: &TomlValue,
    original: &[(OsString, OsString)],
) -> (BTreeMap<OsString, OsString>, Option<String>) {
    let mut result = clean_environment(original);
    match suite.get("paper_fixture").and_then(TomlValue::as_str) {
        Some("evaluator-load") => {
            result.insert("MEMORY_V1_LOAD_ITERATIONS".into(), "1000".into());
            result.insert("MEMORY_V1_LOAD_ROUNDS".into(), "3".into());
        }
        Some(mode @ ("http-default" | "http-expanded")) => {
            let extra = if mode == "http-default" { "0" } else { "128" };
            result.insert("ASTRAL_MEMORY_V1_ALLOW_CURVE".into(), extra.into());
        }
        _ => {}
    }
    let problem = validate_suite(suite).err();
    (result, problem)
}

pub(super) fn mysql_environment(
    original: &[(OsString, OsString)],
    run: &str,
    allowed: bool,
) -> Result<BTreeMap<OsString, OsString>, String> {
    if !allowed {
        return Err(
            "the MySQL suite requires the dedicated --paper --mysql entry, not a generic suite run"
                .into(),
        );
    }
    if !cfg!(unix) {
        return Err("the MySQL fixture requires Unix credentials and drain support".into());
    }
    let lookup = |key: &str| {
        original
            .iter()
            .find(|(name, _)| name == key)
            .and_then(|(_, value)| value.to_str())
    };
    let approved = lookup(mysql_scope::APPROVAL_ENV)
        .ok_or("missing operator approval for the dedicated MySQL fixture")?;
    let raw = lookup(mysql_scope::URL_ENV).ok_or("missing dedicated paper MySQL fixture URL")?;
    let url = url::Url::parse(raw).map_err(|_| "invalid dedicated paper MySQL fixture URL")?;
    mysql_scope::validate(&url, run, approved)?;
    let bundle =
        Path::new(lookup(mysql_scope::BUNDLE_ENV).ok_or("missing prepared paper startup bundle")?);
    let expected = format!("paper-startup-{run}");
    if !bundle.is_absolute()
        || bundle.file_name().and_then(|name| name.to_str()) != Some(&expected)
        || bundle.canonicalize().ok().as_deref() != Some(bundle)
        || !bundle.is_dir()
    {
        return Err("paper startup bundle must be the exact canonical run directory".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(bundle)
            .map_err(|_| "unavailable paper startup bundle")?
            .permissions()
            .mode()
            & 0o7777
            != 0o700
        {
            return Err("paper startup bundle must be private (0700)".into());
        }
    }
    let mut result = BTreeMap::from([
        (mysql_scope::BUNDLE_ENV.into(), bundle.as_os_str().into()),
        (mysql_scope::URL_ENV.into(), raw.into()),
        (mysql_scope::APPROVAL_ENV.into(), approved.into()),
        (mysql_scope::RUN_ENV.into(), run.into()),
    ]);
    if let Some(prepare) = lookup(mysql_scope::PREPARE_ENV) {
        if prepare != run {
            return Err("paper preparation approval must match this run".into());
        }
        result.insert(mysql_scope::PREPARE_ENV.into(), prepare.into());
    }
    Ok(result)
}

pub(super) fn fixture_settings(
    env: &BTreeMap<OsString, OsString>,
) -> BTreeMap<&'static str, String> {
    [
        "MEMORY_V1_LOAD_ITERATIONS",
        "MEMORY_V1_LOAD_ROUNDS",
        "ASTRAL_MEMORY_V1_ALLOW_CURVE",
    ]
    .into_iter()
    .filter_map(|key| {
        let value = env.get(std::ffi::OsStr::new(key))?.to_str()?;
        Some((key, value.to_owned()))
    })
    .collect()
}

pub(super) fn loopback_preflight(suite: &TomlValue) -> Option<String> {
    if suite.get("paper_lane").and_then(TomlValue::as_str) != Some("loopback")
        && !is_mysql_suite(suite)
    {
        return None;
    }
    if !cfg!(unix) {
        return Some("paper loopback fixtures require Unix credential-file modes".into());
    }
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .err()
        .map(|error| format!("loopback TCP preflight: {error}"))
}

pub(super) fn check_mysql_evidence(stdout: &str, mut result: Value) -> Value {
    const PHASES: [&str; 4] = [
        "snapshot_exact",
        "cold_release",
        "warm_publications",
        "retained_unchanged",
    ];
    let phases = stdout
        .lines()
        .filter_map(|line| {
            let (_, body) = line.split_once("paper-mysql: ")?;
            body.split_whitespace().next()
        })
        .collect::<Vec<_>>();
    result["paper_mysql_phases"] = json!(phases);
    if phases != PHASES {
        result["status"] = json!("FAIL");
        result["reason"] = json!("missing or out-of-order MySQL evidence postconditions");
    } else {
        result["reason"] = json!(
            "real snapshot, private link cutoff, warm publications and unchanged fixture verified"
        );
    }
    result
}

pub(super) fn check_measurements(suite: &TomlValue, output: &str, result: &Value) -> Option<Value> {
    let marker = suite.get("paper_measurement")?.as_str()?;
    let expected = suite.get("paper_rows")?.as_integer()? as usize;
    let mut keys = std::collections::BTreeSet::new();
    let mut rows = 0;
    let mut valid = true;
    let mut owner_phases = std::collections::BTreeSet::new();
    // With one libtest worker and --nocapture, its first row may follow the test label.
    for line in output.lines().map(str::trim_start) {
        let line = if line.starts_with("test ") {
            line.split_once(" ... ").map_or(line, |(_, body)| body)
        } else {
            line
        };
        if marker == "client RTT " {
            if let Some((phase, sample)) = line.split_once(": count=") {
                if let Some(count) = sample
                    .split_whitespace()
                    .next()
                    .and_then(|raw| raw.parse::<usize>().ok())
                {
                    match phase {
                        "commit/binding" | "commit/journal_io" | "commit/root_cas"
                        | "commit/total"
                            if count == 24 =>
                        {
                            valid &= owner_phases.insert(phase);
                        }
                        "deny/journal_io" | "deny/total" if count == 16 => {
                            valid &= owner_phases.insert(phase);
                        }
                        _ => {}
                    }
                }
            }
        }
        if !line.starts_with(marker) {
            continue;
        }
        rows += 1;
        let key = if marker == "client RTT " {
            line.split_whitespace().nth(2).map(|kind| vec![kind])
        } else {
            let fields = line
                .split_whitespace()
                .filter_map(|field| field.split_once('='))
                .collect::<BTreeMap<_, _>>();
            let dimensions: &[&str] = if marker.starts_with("allow_read ") {
                &["keep_alive", "workers", "round"]
            } else if marker == "rules=" {
                &["rules", "workers", "round"]
            } else {
                &["workers", "round"]
            };
            dimensions
                .iter()
                .map(|name| fields.get(name).copied())
                .collect::<Option<Vec<_>>>()
        };
        valid &= key.is_some_and(|key| keys.insert(key));
    }
    let mut result = result.clone();
    result["measurement"] = json!({"rows":rows,"expected_rows":expected,"unique_cells":keys.len(),
        "scope":"fresh fixture measurement; no historical timing comparison"});
    if marker == "client RTT " {
        valid &=
            keys.iter().map(|key| key[0]).eq(["ALLOW", "DENY", "LOGIN"]) && owner_phases.len() == 6;
        result["measurement"]["owner_phases"] = json!(owner_phases);
    }
    if rows != expected || !valid {
        result["status"] = json!("FAIL");
        result["reason"] = json!("incomplete, unexpected or duplicate paper measurement cells");
    }
    Some(result)
}

pub fn run_paper_options(root: &Path, args: &[String]) -> Result<i32, String> {
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "-h" | "--help"))
    {
        print!("{PAPER_USAGE}");
        return Ok(0);
    }
    let options = PaperOptions::parse(args)?;
    let manifest = read_manifest(root)?;
    let (ids, plan) = options.plan(&manifest)?;
    if options.list {
        println!("{}", serde_json::to_string_pretty(&plan).unwrap());
        return Ok(0);
    }
    let suites = select_suites(&manifest, &[], &[], &ids, true, false)?;
    #[cfg(unix)]
    let _interrupts = InterruptGuard::install()?;
    let original = env::vars_os().collect::<Vec<_>>();
    run_selected_with_runtime(
        &manifest,
        &suites,
        &options.common.run_id,
        &options.common.artifact_root,
        false,
        SelectedRuntime {
            environment: &original,
            snapshot: snapshot_hash,
            execute_command: super::execute,
            paper: Some(plan),
            darkstar: None,
        },
    )
}
