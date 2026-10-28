use regex::RegexBuilder;
use serde_json::Value;
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, ExitStatus, Stdio};
use std::sync::mpsc::{self, SyncSender};
use std::thread::{self, JoinHandle};
use uuid::Uuid;

const FUTURE_INCOMPAT_REPORT: &str = ".future-incompat-report.json";

fn main() -> ExitCode {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        eprintln!("usage: cargo-no-warnings <cargo-subcommand> [arguments...]");
        return ExitCode::from(2);
    }

    let current_dir = match std::env::current_dir() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("error: failed to determine the current directory: {error}");
            return ExitCode::FAILURE;
        }
    };
    let target_dir = resolve_target_dir(&current_dir, std::env::var_os("CARGO_TARGET_DIR"));
    let mut executor = ProcessCargoExecutor;
    let stdout = io::stdout();
    let mut stdout = stdout.lock();

    match run_gate(&args, &target_dir, &mut executor, &mut stdout) {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            eprintln!("{}", failure.message);
            ExitCode::from(failure.exit_code.clamp(0, 255) as u8)
        }
    }
}

fn resolve_target_dir(current_dir: &Path, configured: Option<OsString>) -> PathBuf {
    let configured = configured.unwrap_or_else(|| OsString::from("target"));
    let path = PathBuf::from(configured);
    if path.is_absolute() {
        path
    } else {
        current_dir.join(path)
    }
}

fn run_gate(
    args: &[OsString],
    target_dir: &Path,
    executor: &mut dyn CargoExecutor,
    stdout: &mut dyn Write,
) -> Result<(), GateFailure> {
    if args.is_empty() {
        return Err(GateFailure::new(
            2,
            "usage: cargo-no-warnings <cargo-subcommand> [arguments...]",
        ));
    }

    fs::create_dir_all(target_dir).map_err(|error| {
        GateFailure::new(
            1,
            format!("error: failed to prepare Cargo target directory: {error}"),
        )
    })?;
    let report_path = target_dir.join(FUTURE_INCOMPAT_REPORT);
    match fs::remove_file(&report_path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(GateFailure::new(
                1,
                format!("error: failed to clear the old future-incompatibility report: {error}"),
            ));
        }
    }

    let command_line = format!("+ cargo --color never{}\n", format_arguments(args));
    stdout.write_all(command_line.as_bytes()).map_err(|error| {
        GateFailure::new(
            1,
            format!("error: failed to capture the Cargo command output: {error}"),
        )
    })?;
    stdout.flush().map_err(|error| {
        GateFailure::new(
            1,
            format!("error: failed to capture the Cargo command output: {error}"),
        )
    })?;

    let mut log = TempLog::create().map_err(|error| {
        GateFailure::new(
            1,
            format!("error: failed to create the Cargo output log: {error}"),
        )
    })?;
    let (execution, capture_errors) = {
        let mut capture = TeeCapture::new(stdout, &mut log.file);
        let execution = executor.execute(args, target_dir, &mut capture);
        capture.finish();
        (execution, capture.errors())
    };

    if let Some(log_error) = capture_errors.log.as_ref() {
        let status = execution_status(&execution);
        return Err(GateFailure::new(
            status.unwrap_or(1),
            format!("error: failed to capture the complete Cargo output log: {log_error}"),
        ));
    }

    let output = log.read_all().map_err(|error| {
        GateFailure::new(
            execution_status(&execution).unwrap_or(1),
            format!("error: failed to read the complete Cargo output log: {error}"),
        )
    })?;
    if contains_cargo_warning(&output) {
        return Err(GateFailure::new(
            1,
            "error: Cargo emitted a warning; this CI gate requires zero warnings.",
        ));
    }

    let packages = read_future_incompat_packages(&report_path)?;
    if !packages.is_empty() {
        return Err(GateFailure::new(
            1,
            format!(
                "error: future-incompatibility warnings reported for: {}",
                packages.join(", ")
            ),
        ));
    }

    let cargo_status = execution?;
    if cargo_status != 0 {
        let capture_note = capture_errors
            .stdout
            .map(|error| format!(" Output capture also failed: {error}."))
            .unwrap_or_default();
        return Err(GateFailure::new(
            cargo_status,
            format!("error: Cargo exited with status {cargo_status}.{capture_note}"),
        ));
    }
    if let Some(error) = capture_errors.stdout {
        return Err(GateFailure::new(
            1,
            format!("error: failed to capture the complete Cargo output: {error}"),
        ));
    }

    Ok(())
}

fn format_arguments(args: &[OsString]) -> String {
    args.iter()
        .map(|argument| format!(" {}", shell_quote(argument)))
        .collect::<String>()
}

fn shell_quote(argument: &OsStr) -> String {
    let argument = argument.to_string_lossy();
    let safe = !argument.is_empty()
        && argument
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"@%_+=:,./-".contains(&byte));
    if safe {
        argument.into_owned()
    } else {
        format!("'{}'", argument.replace('\'', "'\\''"))
    }
}

fn contains_cargo_warning(output: &[u8]) -> bool {
    let text = String::from_utf8_lossy(output);
    RegexBuilder::new(r"(^|\s)warning(\[[^\]]+\])?:|cargo:warning=")
        .case_insensitive(true)
        .build()
        .expect("static Cargo warning expression must compile")
        .is_match(&text)
}

fn read_future_incompat_packages(report_path: &Path) -> Result<Vec<String>, GateFailure> {
    let bytes = match fs::read(report_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(GateFailure::new(
                1,
                format!("error: failed to read future-incompatibility report: {error}"),
            ));
        }
    };
    parse_future_incompat_packages(&bytes).map_err(|error| {
        GateFailure::new(
            1,
            format!("error: malformed future-incompatibility report: {error}"),
        )
    })
}

fn parse_future_incompat_packages(bytes: &[u8]) -> Result<Vec<String>, String> {
    let report: Value = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    let root = report
        .as_object()
        .ok_or_else(|| "top-level value must be an object".to_owned())?;
    let Some(reports) = root.get("reports") else {
        return Ok(Vec::new());
    };
    let reports = reports
        .as_array()
        .ok_or_else(|| "reports must be an array".to_owned())?;
    let mut packages = BTreeSet::new();
    for (index, item) in reports.iter().enumerate() {
        let item = item
            .as_object()
            .ok_or_else(|| format!("reports[{index}] must be an object"))?;
        match item.get("per_package") {
            None => {}
            Some(Value::Object(per_package)) => packages.extend(per_package.keys().cloned()),
            Some(_) => {
                return Err(format!("reports[{index}].per_package must be an object"));
            }
        }
    }
    Ok(packages.into_iter().collect())
}

trait CargoExecutor {
    fn execute(
        &mut self,
        args: &[OsString],
        target_dir: &Path,
        capture: &mut TeeCapture<'_>,
    ) -> Result<i32, GateFailure>;
}

struct ProcessCargoExecutor;

impl CargoExecutor for ProcessCargoExecutor {
    fn execute(
        &mut self,
        args: &[OsString],
        _target_dir: &Path,
        capture: &mut TeeCapture<'_>,
    ) -> Result<i32, GateFailure> {
        let mut command = Command::new("cargo");
        command
            .arg("--color")
            .arg("never")
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().map_err(|error| {
            let status = match error.kind() {
                io::ErrorKind::NotFound => 127,
                io::ErrorKind::PermissionDenied => 126,
                _ => 1,
            };
            GateFailure::new(status, format!("error: failed to start Cargo: {error}"))
        })?;

        let Some(child_stdout) = child.stdout.take() else {
            terminate_child(&mut child);
            return Err(GateFailure::new(
                1,
                "error: Cargo stdout pipe was unavailable.",
            ));
        };
        let Some(child_stderr) = child.stderr.take() else {
            terminate_child(&mut child);
            return Err(GateFailure::new(
                1,
                "error: Cargo stderr pipe was unavailable.",
            ));
        };

        let (sender, receiver) = mpsc::sync_channel(16);
        let stdout_reader = match spawn_reader(child_stdout, sender.clone(), "cargo-stdout") {
            Ok(reader) => reader,
            Err(error) => {
                terminate_child(&mut child);
                return Err(GateFailure::new(
                    1,
                    format!("error: failed to capture Cargo stdout: {error}"),
                ));
            }
        };
        let stderr_reader = match spawn_reader(child_stderr, sender.clone(), "cargo-stderr") {
            Ok(reader) => reader,
            Err(error) => {
                let _ = child.kill();
                drop(sender);
                drop(receiver);
                let _ = stdout_reader.join();
                terminate_child(&mut child);
                return Err(GateFailure::new(
                    1,
                    format!("error: failed to capture Cargo stderr: {error}"),
                ));
            }
        };
        drop(sender);

        let mut read_error = None;
        for event in receiver {
            match event {
                Ok(bytes) => capture.write_bytes(&bytes),
                Err(error) => {
                    read_error.get_or_insert_with(|| error.to_string());
                    let _ = child.kill();
                }
            }
        }
        let stdout_panicked = stdout_reader.join().is_err();
        let stderr_panicked = stderr_reader.join().is_err();
        let status = child.wait().map_err(|error| {
            GateFailure::new(1, format!("error: failed to wait for Cargo: {error}"))
        })?;
        let exit_code = status_exit_code(status);

        if let Some(error) = read_error {
            return Err(GateFailure::new(
                exit_code.max(1),
                format!("error: failed while reading Cargo output: {error}"),
            ));
        }
        if stdout_panicked || stderr_panicked {
            return Err(GateFailure::new(
                exit_code.max(1),
                "error: a Cargo output reader stopped unexpectedly.",
            ));
        }
        Ok(exit_code)
    }
}

fn spawn_reader<R>(
    mut reader: R,
    sender: SyncSender<io::Result<Vec<u8>>>,
    name: &'static str,
) -> io::Result<JoinHandle<()>>
where
    R: Read + Send + 'static,
{
    thread::Builder::new().name(name.to_owned()).spawn(move || {
        let mut buffer = [0_u8; 8192];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => return,
                Ok(length) => {
                    if sender.send(Ok(buffer[..length].to_vec())).is_err() {
                        return;
                    }
                }
                Err(error) => {
                    let _ = sender.send(Err(error));
                    return;
                }
            }
        }
    })
}

fn terminate_child(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn status_exit_code(status: ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        status.signal().map_or(1, |signal| 128 + signal)
    }
    #[cfg(not(unix))]
    {
        1
    }
}

fn execution_status(execution: &Result<i32, GateFailure>) -> Option<i32> {
    match execution {
        Ok(status) if *status != 0 => Some(*status),
        Err(failure) if failure.exit_code != 0 => Some(failure.exit_code),
        _ => None,
    }
}

#[derive(Debug, PartialEq, Eq)]
struct GateFailure {
    exit_code: i32,
    message: String,
}

impl GateFailure {
    fn new(exit_code: i32, message: impl Into<String>) -> Self {
        Self {
            exit_code,
            message: message.into(),
        }
    }
}

#[derive(Default)]
struct CaptureErrors {
    stdout: Option<String>,
    log: Option<String>,
}

struct TeeCapture<'a> {
    stdout: &'a mut dyn Write,
    log: &'a mut dyn Write,
    errors: CaptureErrors,
}

impl<'a> TeeCapture<'a> {
    fn new(stdout: &'a mut dyn Write, log: &'a mut dyn Write) -> Self {
        Self {
            stdout,
            log,
            errors: CaptureErrors::default(),
        }
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        if let Err(error) = self.stdout.write_all(bytes) {
            self.errors.stdout.get_or_insert_with(|| error.to_string());
        }
        if let Err(error) = self.log.write_all(bytes) {
            self.errors.log.get_or_insert_with(|| error.to_string());
        }
    }

    fn finish(&mut self) {
        if let Err(error) = self.stdout.flush() {
            self.errors.stdout.get_or_insert_with(|| error.to_string());
        }
        if let Err(error) = self.log.flush() {
            self.errors.log.get_or_insert_with(|| error.to_string());
        }
    }

    fn errors(&self) -> CaptureErrors {
        CaptureErrors {
            stdout: self.errors.stdout.clone(),
            log: self.errors.log.clone(),
        }
    }
}

struct TempLog {
    path: PathBuf,
    file: File,
}

impl TempLog {
    fn create() -> io::Result<Self> {
        for _ in 0..8 {
            let path =
                std::env::temp_dir().join(format!("cargo-no-warnings-{}.log", Uuid::new_v4()));
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(file) => return Ok(Self { path, file }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique temporary Cargo log",
        ))
    }

    fn read_all(&mut self) -> io::Result<Vec<u8>> {
        self.file.flush()?;
        self.file.seek(SeekFrom::Start(0))?;
        let mut contents = Vec::new();
        self.file.read_to_end(&mut contents)?;
        Ok(contents)
    }
}

impl Drop for TempLog {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::min;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("cargo-no-warnings-test-{label}-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct FakeCargo {
        output: Vec<u8>,
        status: i32,
        report: Option<Vec<u8>>,
        called: bool,
    }

    impl FakeCargo {
        fn new(output: &[u8], status: i32) -> Self {
            Self {
                output: output.to_vec(),
                status,
                report: None,
                called: false,
            }
        }

        fn with_report(mut self, report: &[u8]) -> Self {
            self.report = Some(report.to_vec());
            self
        }
    }

    impl CargoExecutor for FakeCargo {
        fn execute(
            &mut self,
            _args: &[OsString],
            target_dir: &Path,
            capture: &mut TeeCapture<'_>,
        ) -> Result<i32, GateFailure> {
            self.called = true;
            capture.write_bytes(&self.output);
            if let Some(report) = &self.report {
                fs::write(target_dir.join(FUTURE_INCOMPAT_REPORT), report).map_err(|error| {
                    GateFailure::new(
                        1,
                        format!("fixture could not write future-incompatibility report: {error}"),
                    )
                })?;
            }
            Ok(self.status)
        }
    }

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn run_fake(
        directory: &TestDirectory,
        cargo: &mut FakeCargo,
        stdout: &mut dyn Write,
    ) -> Result<(), GateFailure> {
        run_gate(&args(&["check"]), directory.path(), cargo, stdout)
    }

    #[test]
    fn rejects_regular_cargo_warning_lines() {
        let directory = TestDirectory::new("warning");
        let mut cargo = FakeCargo::new(b"Checking probe\nwarning: deliberate warning probe\n", 0);
        let mut output = Vec::new();

        let failure = run_fake(&directory, &mut cargo, &mut output).unwrap_err();

        assert_eq!(failure.exit_code, 1);
        assert!(failure.message.contains("Cargo emitted a warning"));
        assert!(output.ends_with(b"warning: deliberate warning probe\n"));
    }

    #[test]
    fn rejects_build_script_cargo_warning_lines() {
        let directory = TestDirectory::new("cargo-warning");
        let mut cargo = FakeCargo::new(b"cargo:warning=deliberate build-script warning\n", 0);
        let mut output = Vec::new();

        let failure = run_fake(&directory, &mut cargo, &mut output).unwrap_err();

        assert_eq!(failure.exit_code, 1);
        assert!(failure.message.contains("Cargo emitted a warning"));
    }

    #[test]
    fn rejects_nonempty_future_incompatibility_packages() {
        let directory = TestDirectory::new("future-incompat");
        let report = br#"{"reports":[{"per_package":{"probe@0.1.0":"future warning"}}]}"#;
        let mut cargo = FakeCargo::new(b"Finished dev profile\n", 0).with_report(report);
        let mut output = Vec::new();

        let failure = run_fake(&directory, &mut cargo, &mut output).unwrap_err();

        assert_eq!(failure.exit_code, 1);
        assert!(failure
            .message
            .contains("future-incompatibility warnings reported"));
        assert!(failure.message.contains("probe@0.1.0"));
    }

    #[test]
    fn returns_the_cargo_failure_exit_code_and_keeps_its_raw_output() {
        let directory = TestDirectory::new("failure-42");
        let mut cargo = FakeCargo::new(b"error: deliberate command failure\n", 42);
        let mut output = Vec::new();

        let failure = run_fake(&directory, &mut cargo, &mut output).unwrap_err();

        assert_eq!(failure.exit_code, 42);
        assert!(failure.message.contains("status 42"));
        assert!(output.ends_with(b"error: deliberate command failure\n"));
    }

    #[test]
    fn clears_stale_future_report_before_a_clean_success() {
        let directory = TestDirectory::new("stale-report");
        let report_path = directory.path().join(FUTURE_INCOMPAT_REPORT);
        fs::write(
            &report_path,
            br#"{"reports":[{"per_package":{"stale@0.1.0":"old warning"}}]}"#,
        )
        .unwrap();
        let mut cargo = FakeCargo::new(b"Finished dev profile\n", 0);
        let mut output = Vec::new();

        run_fake(&directory, &mut cargo, &mut output).unwrap();

        assert!(!report_path.exists());
        assert!(output.ends_with(b"Finished dev profile\n"));
    }

    #[test]
    fn clean_success_prints_the_original_command_header_and_raw_output() {
        let directory = TestDirectory::new("clean-success");
        let mut cargo = FakeCargo::new(b"Finished dev profile\n", 0);
        let mut output = Vec::new();

        run_fake(&directory, &mut cargo, &mut output).unwrap();

        assert_eq!(
            output,
            b"+ cargo --color never check\nFinished dev profile\n"
        );
    }

    #[test]
    fn rejects_malformed_future_incompatibility_reports() {
        for (label, report) in [
            ("invalid-json", b"{not json".as_slice()),
            ("invalid-shape", br#"{"reports":{}}"#.as_slice()),
        ] {
            let directory = TestDirectory::new(label);
            let mut cargo = FakeCargo::new(b"Finished dev profile\n", 0).with_report(report);
            let mut output = Vec::new();

            let failure = run_fake(&directory, &mut cargo, &mut output).unwrap_err();

            assert_eq!(failure.exit_code, 1, "{label}");
            assert!(failure
                .message
                .contains("malformed future-incompatibility report"));
        }
    }

    struct FailAfterPrefix {
        remaining: usize,
    }

    impl Write for FailAfterPrefix {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "fixture output capture failure",
                ));
            }
            let length = min(self.remaining, bytes.len());
            self.remaining -= length;
            Ok(length)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn fails_when_cargo_output_cannot_be_captured() {
        let directory = TestDirectory::new("capture-failure");
        let mut cargo = FakeCargo::new(b"raw output that cannot reach stdout\n", 0);
        let header = b"+ cargo --color never check\n";
        let mut output = FailAfterPrefix {
            remaining: header.len(),
        };

        let failure = run_fake(&directory, &mut cargo, &mut output).unwrap_err();

        assert!(cargo.called);
        assert_eq!(failure.exit_code, 1);
        assert!(failure
            .message
            .contains("failed to capture the complete Cargo output"));
    }
}
