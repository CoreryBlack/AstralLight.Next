//! Private implementation for the explicit ROOT source-bootstrap operator.
//!
//! This module deliberately has no startup or HTTP integration. It validates
//! all argv and local-file inputs before network/database access, emits one
//! redacted JSON result, and never prints credential material, URLs, or raw
//! dependency errors.

use std::{
    env, fs,
    io::Read as _,
    path::{Path, PathBuf},
    time::Duration,
};

use astral_authority::client::{AuthorityClient, AuthorityClientConfig};
use astral_authority::AuthorityClientError;
use astral_db::authority_source_bootstrap::{
    create_source_bootstrap, preflight_source_bootstrap, reconcile_source_bootstrap_db,
    SourceBootstrapAuditContext, VerifiedSourceBootstrapPermit,
};
use astral_types::{
    authority_protocol::AUTHORITY_MAX_BODY_BYTES, AuthoritySourceBootstrapCompletion,
    AuthoritySourceBootstrapState, AuthoritySourceBootstrapTicket, PolicyError,
};
use serde::Serialize;
use serde_json::json;
use sqlx::mysql::MySqlPoolOptions;

const MAX_PATH_BYTES: usize = 4 * 1024;
const MAX_PEM_BYTES: usize = 1024 * 1024;
const DEFAULT_TIMEOUT_SECONDS: u64 = 10;
const DEFAULT_AUTHORITY_URL_ENV: &str = "ASTRAL_AUTHORITY_URL";
const DEFAULT_GENESIS_DIGEST_ENV: &str = "ASTRAL_AUTHORITY_GENESIS_TRUST_ROOT_DIGEST";
const DEFAULT_DATABASE_URL_ENV: &str = "DATABASE_URL";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExitCode {
    Ok = 0,
    InvalidInput = 2,
    Blocked = 3,
    Unknown = 4,
    Failed = 5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommandKind {
    Preflight,
    Prepare,
    Apply,
    Reconcile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailureClass {
    Blocked,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ClassifiedFailure {
    class: FailureClass,
    reason: &'static str,
}

impl ClassifiedFailure {
    const fn blocked(reason: &'static str) -> Self {
        Self {
            class: FailureClass::Blocked,
            reason,
        }
    }

    const fn failed(reason: &'static str) -> Self {
        Self {
            class: FailureClass::Failed,
            reason,
        }
    }

    const fn unknown(reason: &'static str) -> Self {
        Self {
            class: FailureClass::Unknown,
            reason,
        }
    }

    const fn status(self) -> &'static str {
        match self.class {
            FailureClass::Blocked => "BLOCKED",
            FailureClass::Failed => "FAILED",
            FailureClass::Unknown => "UNKNOWN",
        }
    }

    const fn exit_code(self) -> ExitCode {
        match self.class {
            FailureClass::Blocked => ExitCode::Blocked,
            FailureClass::Failed => ExitCode::Failed,
            FailureClass::Unknown => ExitCode::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Command {
    kind: CommandKind,
    ticket_path: PathBuf,
    ca_path: PathBuf,
    identity_path: PathBuf,
    authority_url_env: String,
    genesis_digest_env: String,
    database_url_env: String,
    actor_user_id: Option<i64>,
    timeout_seconds: u64,
}

#[derive(Debug, Clone)]
struct Inputs {
    ticket: AuthoritySourceBootstrapTicket,
    ticket_digest: String,
    payload_digest: String,
    client: AuthorityClient,
    database_url: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Output {
    status: &'static str,
    command: &'static str,
    reason: &'static str,
    operation_id: Option<String>,
    ticket_digest: Option<String>,
    payload_digest: Option<String>,
    source_completion: &'static str,
    authority_completion: &'static str,
    certificate_publication: &'static str,
    readiness: &'static str,
    db_reconciliation: &'static str,
    quorum_reconciliation: &'static str,
    replayed: bool,
    lease_aborted: bool,
}

impl Output {
    fn new(command: &'static str, status: &'static str, reason: &'static str) -> Self {
        Self {
            status,
            command,
            reason,
            operation_id: None,
            ticket_digest: None,
            payload_digest: None,
            source_completion: "NOT_PROVEN",
            authority_completion: "NOT_PROVEN",
            certificate_publication: "NOT_PROVEN",
            readiness: "NOT_PROVEN",
            db_reconciliation: "NOT_RUN",
            quorum_reconciliation: "NOT_RUN",
            replayed: false,
            lease_aborted: false,
        }
    }

    fn with_identity(mut self, inputs: &Inputs) -> Self {
        self.operation_id = Some(inputs.ticket.operation_id.clone());
        self.ticket_digest = Some(inputs.ticket_digest.clone());
        self.payload_digest = Some(inputs.payload_digest.clone());
        self
    }
}

pub async fn run(args: Vec<String>) -> i32 {
    let command = match parse_args(&args) {
        Ok(command) => command,
        Err(reason) => {
            emit(Output::new("unknown", "INVALID_INPUT", reason));
            return ExitCode::InvalidInput as i32;
        }
    };

    let command_name = command_name(command.kind);
    let local = match read_ticket_and_local_inputs(&command) {
        Ok(local) => local,
        Err(reason) => {
            let failure = ClassifiedFailure::blocked(reason);
            emit(Output::new(command_name, failure.status(), failure.reason));
            return failure.exit_code() as i32;
        }
    };

    match command.kind {
        CommandKind::Preflight => preflight(local, &command, command_name).await,
        CommandKind::Prepare => prepare(local, &command, command_name).await,
        CommandKind::Apply => apply(local, command, command_name).await,
        CommandKind::Reconcile => reconcile(local, &command, command_name).await,
    }
}

fn parse_args(args: &[String]) -> Result<Command, &'static str> {
    if args.is_empty() {
        return Err("COMMAND_REQUIRED");
    }
    let kind = match args[0].as_str() {
        "preflight" => CommandKind::Preflight,
        "prepare" => CommandKind::Prepare,
        "apply" => CommandKind::Apply,
        "reconcile" => CommandKind::Reconcile,
        "help" => return Err("HELP_USE_COMMAND_USAGE"),
        _ => return Err("COMMAND_INVALID"),
    };

    let mut ticket_path = None;
    let mut ca_path = None;
    let mut identity_path = None;
    let mut authority_url_env = DEFAULT_AUTHORITY_URL_ENV.to_owned();
    let mut genesis_digest_env = DEFAULT_GENESIS_DIGEST_ENV.to_owned();
    let mut database_url_env = DEFAULT_DATABASE_URL_ENV.to_owned();
    let mut actor_user_id = None;
    let mut timeout_seconds = DEFAULT_TIMEOUT_SECONDS;
    let mut index = 1;
    let mut seen_flags = std::collections::BTreeSet::new();

    while index < args.len() {
        let flag = args[index].as_str();
        if !seen_flags.insert(flag) {
            return Err("OPTION_DUPLICATED");
        }
        let value = args.get(index + 1).ok_or("OPTION_VALUE_REQUIRED")?.as_str();
        match flag {
            "--ticket" => ticket_path = Some(parse_path(value)?),
            "--ca" => ca_path = Some(parse_path(value)?),
            "--identity" => identity_path = Some(parse_path(value)?),
            "--authority-url-env" => authority_url_env = parse_env_name(value)?,
            "--genesis-digest-env" => genesis_digest_env = parse_env_name(value)?,
            "--database-url-env" => database_url_env = parse_env_name(value)?,
            "--actor-user-id" => {
                let parsed = value.parse::<i64>().map_err(|_| "ACTOR_ID_INVALID")?;
                if parsed <= 0 {
                    return Err("ACTOR_ID_INVALID");
                }
                actor_user_id = Some(parsed);
            }
            "--timeout-seconds" => {
                timeout_seconds = value.parse::<u64>().map_err(|_| "TIMEOUT_INVALID")?;
                if !(1..=120).contains(&timeout_seconds) {
                    return Err("TIMEOUT_OUT_OF_RANGE");
                }
            }
            _ => return Err("OPTION_INVALID"),
        }
        index += 2;
    }

    let ticket_path = ticket_path.ok_or("TICKET_PATH_REQUIRED")?;
    let ca_path = ca_path.ok_or("CA_PATH_REQUIRED")?;
    let identity_path = identity_path.ok_or("IDENTITY_PATH_REQUIRED")?;
    if matches!(kind, CommandKind::Apply) && actor_user_id.is_none() {
        return Err("ACTOR_ID_REQUIRED");
    }

    Ok(Command {
        kind,
        ticket_path,
        ca_path,
        identity_path,
        authority_url_env,
        genesis_digest_env,
        database_url_env,
        actor_user_id,
        timeout_seconds,
    })
}

fn parse_path(value: &str) -> Result<PathBuf, &'static str> {
    if value.is_empty() || value.len() > MAX_PATH_BYTES || value.bytes().any(|byte| byte == 0) {
        return Err("PATH_INVALID");
    }
    Ok(PathBuf::from(value))
}

fn parse_env_name(value: &str) -> Result<String, &'static str> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().enumerate().all(|(index, byte)| {
            (index == 0 && (byte == b'_' || byte.is_ascii_uppercase()))
                || (index > 0
                    && (byte == b'_' || byte.is_ascii_uppercase() || byte.is_ascii_digit()))
        })
    {
        return Err("ENV_NAME_INVALID");
    }
    Ok(value.to_owned())
}

fn command_requires_database(kind: CommandKind) -> bool {
    matches!(
        kind,
        CommandKind::Preflight | CommandKind::Prepare | CommandKind::Apply | CommandKind::Reconcile
    )
}

fn database_url_for_command(
    kind: CommandKind,
    value: Option<&str>,
) -> Result<Option<String>, &'static str> {
    if !command_requires_database(kind) {
        return Ok(None);
    }
    let value = value.ok_or("REQUIRED_ENV_MISSING")?.trim();
    if value.is_empty() || value.len() > 4096 || value.bytes().any(|byte| byte == 0) {
        return Err("REQUIRED_ENV_INVALID");
    }
    if !value.starts_with("mysql://") {
        return Err("DATABASE_URL_INVALID");
    }
    Ok(Some(value.to_owned()))
}

fn read_ticket_and_local_inputs(command: &Command) -> Result<Inputs, &'static str> {
    let ticket_bytes = read_bounded_file(&command.ticket_path, AUTHORITY_MAX_BODY_BYTES, "TICKET")?;
    let ticket: AuthoritySourceBootstrapTicket =
        serde_json::from_slice(&ticket_bytes).map_err(|_| "TICKET_JSON_INVALID")?;
    ticket.validate().map_err(|_| "TICKET_INVALID")?;
    let ticket_digest = ticket
        .artifact_digest()
        .map_err(|_| "TICKET_DIGEST_FAILED")?;
    let payload_digest = ticket
        .payload_digest()
        .map_err(|_| "PAYLOAD_DIGEST_FAILED")?;

    let ca = read_bounded_file(&command.ca_path, MAX_PEM_BYTES, "CA")?;
    let identity = read_bounded_file(&command.identity_path, MAX_PEM_BYTES, "IDENTITY")?;
    if ca.is_empty() || identity.is_empty() {
        return Err("CREDENTIAL_FILE_EMPTY");
    }

    let authority_url = read_env(&command.authority_url_env, "AUTHORITY_URL")?;
    if !authority_url.starts_with("https://") || authority_url.len() > 2048 {
        return Err("AUTHORITY_URL_INVALID");
    }
    let genesis_digest = read_env(&command.genesis_digest_env, "GENESIS_DIGEST")?;
    if genesis_digest.len() != 64
        || !genesis_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("GENESIS_DIGEST_INVALID");
    }

    let client = AuthorityClient::new(AuthorityClientConfig {
        base_url: authority_url,
        server_ca_pem: ca,
        client_identity_pem: identity,
        service_id: ticket.service_id.clone(),
        pinned_genesis_trust_root_digest: genesis_digest,
        request_timeout: Duration::from_secs(command.timeout_seconds),
    })
    .map_err(|_| "AUTHORITY_CLIENT_INVALID")?;

    let database_url_value = env::var(&command.database_url_env).ok();
    let database_url = database_url_for_command(command.kind, database_url_value.as_deref())?;

    Ok(Inputs {
        ticket,
        ticket_digest,
        payload_digest,
        client,
        database_url,
    })
}

fn read_bounded_file(path: &Path, limit: usize, _kind: &str) -> Result<Vec<u8>, &'static str> {
    let mut file = fs::File::open(path).map_err(|_| "INPUT_FILE_UNREADABLE")?;
    let metadata = file.metadata().map_err(|_| "INPUT_FILE_UNREADABLE")?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err("INPUT_FILE_TOO_LARGE_OR_NOT_FILE");
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "INPUT_FILE_UNREADABLE")?;
    if bytes.len() > limit {
        return Err("INPUT_FILE_TOO_LARGE");
    }
    Ok(bytes)
}

fn read_env(name: &str, _kind: &str) -> Result<String, &'static str> {
    let value = env::var(name).map_err(|_| "REQUIRED_ENV_MISSING")?;
    let value = value.trim();
    if value.is_empty() || value.len() > 4096 || value.bytes().any(|byte| byte == 0) {
        return Err("REQUIRED_ENV_INVALID");
    }
    Ok(value.to_owned())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DatabasePreflightFailure {
    ConnectTimedOut,
    ConnectFailed,
    SchemaContractInvalid,
    ReadOnlyTimedOut,
}

fn classify_database_preflight_failure(failure: DatabasePreflightFailure) -> ClassifiedFailure {
    let reason = match failure {
        DatabasePreflightFailure::ConnectTimedOut => "DATABASE_CONNECT_TIMED_OUT",
        DatabasePreflightFailure::ConnectFailed => "DATABASE_CONNECT_FAILED",
        DatabasePreflightFailure::SchemaContractInvalid => "SCHEMA_CONTRACT_INVALID",
        DatabasePreflightFailure::ReadOnlyTimedOut => "READ_ONLY_PREFLIGHT_TIMED_OUT",
    };
    ClassifiedFailure::failed(reason)
}

async fn preflight_database(
    inputs: &Inputs,
    command: &Command,
) -> Result<sqlx::MySqlPool, ClassifiedFailure> {
    inputs
        .client
        .verify_source_bootstrap_ticket(&inputs.ticket)
        .await
        .map_err(classify_preflight_authority_error)?;
    let database_url = inputs
        .database_url
        .as_deref()
        .ok_or_else(|| ClassifiedFailure::blocked("DATABASE_URL_NOT_AVAILABLE"))?;
    let pool = tokio::time::timeout(
        command_timeout(command),
        MySqlPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(command_timeout(command))
            .connect(database_url),
    )
    .await
    .map_err(|_| classify_database_preflight_failure(DatabasePreflightFailure::ConnectTimedOut))?
    .map_err(|_| classify_database_preflight_failure(DatabasePreflightFailure::ConnectFailed))?;
    tokio::time::timeout(command_timeout(command), async {
        astral_db::validate_schema_contract(&pool)
            .await
            .map_err(|_| {
                classify_database_preflight_failure(DatabasePreflightFailure::SchemaContractInvalid)
            })?;
        preflight_source_bootstrap(&pool, &inputs.ticket)
            .await
            .map_err(classify_source_preflight_error)
    })
    .await
    .map_err(|_| {
        classify_database_preflight_failure(DatabasePreflightFailure::ReadOnlyTimedOut)
    })??;
    Ok(pool)
}

fn classify_preflight_authority_error(error: AuthorityClientError) -> ClassifiedFailure {
    match error {
        AuthorityClientError::UnknownOutcome { .. } => {
            ClassifiedFailure::unknown("AUTHORITY_OUTCOME_UNKNOWN_RECONCILE_REQUIRED")
        }
        AuthorityClientError::Rejected { .. } => {
            ClassifiedFailure::failed("AUTHORITY_TICKET_REJECTED")
        }
        AuthorityClientError::InsecureEndpoint => {
            ClassifiedFailure::blocked("AUTHORITY_ENDPOINT_INSECURE")
        }
        AuthorityClientError::Attestation(_) => {
            ClassifiedFailure::failed("AUTHORITY_ATTESTATION_FAILED")
        }
        AuthorityClientError::Protocol(_) | AuthorityClientError::ProtocolError(_) => {
            ClassifiedFailure::failed("AUTHORITY_TICKET_INVALID")
        }
        AuthorityClientError::Transport(_) => {
            ClassifiedFailure::failed("AUTHORITY_TRANSPORT_FAILED")
        }
    }
}

fn classify_source_preflight_error(error: PolicyError) -> ClassifiedFailure {
    match error {
        PolicyError::InvalidContext(_) => {
            ClassifiedFailure::failed("SOURCE_TARGET_PREFLIGHT_INVALID")
        }
        PolicyError::Repository(_) => ClassifiedFailure::failed("SOURCE_TARGET_PREFLIGHT_FAILED"),
        PolicyError::CircuitBreakerOpen => {
            ClassifiedFailure::failed("SOURCE_TARGET_PREFLIGHT_CIRCUIT_OPEN")
        }
        PolicyError::Evaluation(_) => {
            ClassifiedFailure::failed("SOURCE_TARGET_PREFLIGHT_EVALUATION_FAILED")
        }
        PolicyError::NotEligible(_) => {
            ClassifiedFailure::failed("SOURCE_TARGET_PREFLIGHT_NOT_ELIGIBLE")
        }
    }
}

fn classify_prepare_error(error: PolicyError) -> ClassifiedFailure {
    match error {
        // The bridge currently erases the original AuthorityClientError into
        // PolicyError::Repository. Preserve UNKNOWN until that boundary keeps
        // the typed authority outcome available to this operator.
        PolicyError::Repository(_) => {
            ClassifiedFailure::unknown("AUTHORITY_PERMIT_OUTCOME_UNKNOWN_RECONCILE_REQUIRED")
        }
        PolicyError::InvalidContext(_) => ClassifiedFailure::failed("AUTHORITY_PERMIT_INVALID"),
        PolicyError::CircuitBreakerOpen => {
            ClassifiedFailure::failed("AUTHORITY_PERMIT_CIRCUIT_OPEN")
        }
        PolicyError::Evaluation(_) => {
            ClassifiedFailure::failed("AUTHORITY_PERMIT_EVALUATION_FAILED")
        }
        PolicyError::NotEligible(_) => ClassifiedFailure::failed("AUTHORITY_PERMIT_NOT_ELIGIBLE"),
    }
}

async fn preflight(inputs: Inputs, command: &Command, command_name: &'static str) -> i32 {
    let result = match preflight_database(&inputs, command).await {
        Ok(_) => Ok(()),
        Err(failure) => Err(failure),
    };
    match result {
        Ok(()) => {
            emit(
                Output::new(
                    command_name,
                    "PREFLIGHT_VALIDATED",
                    "ROOT_TICKET_SCHEMA_AND_TARGETS_VALIDATED",
                )
                .with_identity(&inputs),
            );
            ExitCode::Ok as i32
        }
        Err(failure) => {
            emit(
                Output::new(command_name, failure.status(), failure.reason).with_identity(&inputs),
            );
            failure.exit_code() as i32
        }
    }
}

async fn prepare(inputs: Inputs, command: &Command, command_name: &'static str) -> i32 {
    if let Err(failure) = preflight_database(&inputs, command).await {
        emit(Output::new(command_name, failure.status(), failure.reason).with_identity(&inputs));
        return failure.exit_code() as i32;
    }
    match VerifiedSourceBootstrapPermit::prepare(&inputs.client, inputs.ticket.clone()).await {
        Ok(permit) => {
            let output = Output::new(command_name, "PREPARED", "AUTHORITY_PREPARE_PROVEN")
                .with_identity(&inputs)
                .with_permit(&permit);
            emit(output);
            ExitCode::Ok as i32
        }
        Err(error) => {
            let failure = classify_prepare_error(error);
            let output =
                Output::new(command_name, failure.status(), failure.reason).with_identity(&inputs);
            emit(output);
            failure.exit_code() as i32
        }
    }
}

async fn apply(inputs: Inputs, command: Command, command_name: &'static str) -> i32 {
    let pool = match preflight_database(&inputs, &command).await {
        Ok(pool) => pool,
        Err(failure) => {
            emit(
                Output::new(command_name, failure.status(), failure.reason).with_identity(&inputs),
            );
            return failure.exit_code() as i32;
        }
    };
    let permit = match VerifiedSourceBootstrapPermit::prepare(&inputs.client, inputs.ticket.clone())
        .await
    {
        Ok(permit) => permit,
        Err(error) => {
            let failure = classify_prepare_error(error);
            emit(
                Output::new(command_name, failure.status(), failure.reason).with_identity(&inputs),
            );
            return failure.exit_code() as i32;
        }
    };

    let audit = SourceBootstrapAuditContext {
        actor_user_id: command
            .actor_user_id
            .expect("apply actor validated before execution"),
    };
    let source_result = match tokio::time::timeout(
        command_timeout(&command),
        create_source_bootstrap(&pool, &permit, audit),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => {
            return reconcile_after_uncertainty(
                &pool,
                &inputs,
                &permit,
                command_name,
                command_timeout(&command),
            )
            .await;
        }
    };
    match source_result {
        Ok(receipt) => match inputs
            .client
            .finalize_source_bootstrap(permit.capability().clone(), receipt.completion.clone())
            .await
        {
            Ok(response)
                if reconciliation_decision(
                    Some(&receipt.completion),
                    Some(&response.receipt.completion),
                    false,
                ) == ReconciliationDecision::Completed =>
            {
                let mut output =
                    Output::new(command_name, "COMPLETED", "SOURCE_AND_AUTHORITY_COMPLETED")
                        .with_identity(&inputs)
                        .with_permit(&permit);
                output.source_completion = "PROVEN";
                output.authority_completion = "PROVEN";
                output.certificate_publication = "NOT_PROVEN";
                output.readiness = "NOT_PROVEN";
                output.db_reconciliation = "NOT_REQUIRED";
                output.quorum_reconciliation = "NOT_REQUIRED";
                emit(output);
                ExitCode::Ok as i32
            }
            Ok(_) | Err(_) => {
                reconcile_after_uncertainty(
                    &pool,
                    &inputs,
                    &permit,
                    command_name,
                    command_timeout(&command),
                )
                .await
            }
        },
        Err(error) => {
            if is_unknown_db_commit(&error) {
                reconcile_after_uncertainty(
                    &pool,
                    &inputs,
                    &permit,
                    command_name,
                    command_timeout(&command),
                )
                .await
            } else {
                emit(
                    Output::new(command_name, "FAILED", "SOURCE_TRANSACTION_NOT_COMMITTED")
                        .with_identity(&inputs),
                );
                ExitCode::Failed as i32
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReconciliationDecision {
    Completed,
    Finalize,
    Pending,
    Unknown,
    Conflict,
}

fn reconciliation_decision(
    source: Option<&AuthoritySourceBootstrapCompletion>,
    authority: Option<&AuthoritySourceBootstrapCompletion>,
    exact_reserved: bool,
) -> ReconciliationDecision {
    match (source, authority) {
        (Some(source), Some(authority)) if source == authority && source.validate().is_ok() => {
            ReconciliationDecision::Completed
        }
        (Some(_), Some(_)) => ReconciliationDecision::Conflict,
        (Some(source), None) if source.validate().is_ok() && exact_reserved => {
            ReconciliationDecision::Finalize
        }
        (Some(_), None) => ReconciliationDecision::Pending,
        (None, _) => ReconciliationDecision::Unknown,
    }
}

async fn reconcile_after_uncertainty(
    pool: &sqlx::MySqlPool,
    inputs: &Inputs,
    permit: &VerifiedSourceBootstrapPermit,
    command_name: &'static str,
    timeout: Duration,
) -> i32 {
    let db_result = tokio::time::timeout(timeout, reconcile_source_bootstrap_db(pool, permit))
        .await
        .unwrap_or_else(|_| {
            Err(PolicyError::Repository(
                "source bootstrap DB reconciliation timed out; outcome remains UNKNOWN".into(),
            ))
        });
    let mut quorum_result = inputs
        .client
        .reconcile_source_bootstrap(
            permit.operation_id().to_owned(),
            permit.ticket_digest().to_owned(),
        )
        .await;
    let source = db_result.as_ref().ok().and_then(Option::as_ref);
    let decision_for = |response: &astral_types::AuthoritySourceBootstrapReconcileResponse| {
        let exact_reserved = response.capability.as_ref() == Some(permit.capability())
            && response.reservation.as_ref().is_some_and(|reservation| {
                reservation.state == AuthoritySourceBootstrapState::Reserved
                    && reservation.reservation_id == permit.capability().reservation_id
                    && reservation.operation_id == permit.operation_id()
                    && reservation.ticket_digest == permit.ticket_digest()
            });
        reconciliation_decision(
            source.map(|receipt| &receipt.completion),
            response.receipt.as_ref().map(|receipt| &receipt.completion),
            exact_reserved,
        )
    };
    if quorum_result
        .as_ref()
        .is_ok_and(|response| decision_for(response) == ReconciliationDecision::Finalize)
    {
        // Only the exact durable DB receipt can finish an existing reservation.
        // A lost finalize response is observed once, never followed by source replay.
        let receipt = source.expect("finalize decision requires durable source evidence");
        let _ = inputs
            .client
            .finalize_source_bootstrap(permit.capability().clone(), receipt.completion.clone())
            .await;
        quorum_result = inputs
            .client
            .reconcile_source_bootstrap(
                permit.operation_id().to_owned(),
                permit.ticket_digest().to_owned(),
            )
            .await;
    }
    let db_state = match &db_result {
        Ok(Some(_)) => "PROVEN",
        Ok(None) => "NOT_FOUND",
        Err(_) => "UNKNOWN",
    };
    let quorum_state = match &quorum_result {
        Ok(response) if response.receipt.is_some() => "PROVEN",
        Ok(response) if response.capability.is_some() => "RESERVED",
        Ok(_) => "NOT_FOUND",
        Err(_) => "UNKNOWN",
    };
    let decision = quorum_result
        .as_ref()
        .map(decision_for)
        .unwrap_or(if source.is_some() {
            ReconciliationDecision::Pending
        } else {
            ReconciliationDecision::Unknown
        });
    let (status, reason) = match decision {
        ReconciliationDecision::Completed => {
            ("COMPLETED", "RECONCILIATION_PROVED_EXACT_COMPLETION")
        }
        ReconciliationDecision::Conflict => ("UNKNOWN", "DB_AND_AUTHORITY_COMPLETION_CONFLICT"),
        ReconciliationDecision::Finalize | ReconciliationDecision::Pending => {
            ("PENDING", "SOURCE_COMMITTED_AUTHORITY_NOT_COMPLETED")
        }
        ReconciliationDecision::Unknown => {
            ("UNKNOWN", "COMMIT_OUTCOME_NOT_PROVEN_RECONCILE_REQUIRED")
        }
    };
    let mut output = Output::new(command_name, status, reason).with_identity(inputs);
    output.source_completion = if source.is_some() {
        "PROVEN"
    } else {
        "NOT_PROVEN"
    };
    output.authority_completion = if decision == ReconciliationDecision::Completed {
        "PROVEN"
    } else {
        "NOT_PROVEN"
    };
    output.db_reconciliation = db_state;
    output.quorum_reconciliation = if decision == ReconciliationDecision::Conflict {
        "CONFLICT"
    } else {
        quorum_state
    };
    emit(output);
    if decision == ReconciliationDecision::Completed {
        ExitCode::Ok as i32
    } else {
        ExitCode::Unknown as i32
    }
}

async fn reconcile(inputs: Inputs, command: &Command, command_name: &'static str) -> i32 {
    let permit =
        match VerifiedSourceBootstrapPermit::reconcile(&inputs.client, inputs.ticket.clone()).await
        {
            Ok(Some(permit)) => permit,
            Ok(None) => {
                emit(
                    Output::new(command_name, "UNKNOWN", "NO_DURABLE_RESERVATION_FOUND")
                        .with_identity(&inputs),
                );
                return ExitCode::Unknown as i32;
            }
            Err(error) => {
                emit(
                    Output::new(command_name, "UNKNOWN", authority_error_reason(&error))
                        .with_identity(&inputs),
                );
                return ExitCode::Unknown as i32;
            }
        };
    let Some(database_url) = inputs.database_url.as_deref() else {
        emit(
            Output::new(command_name, "BLOCKED", "DATABASE_URL_NOT_AVAILABLE")
                .with_identity(&inputs),
        );
        return ExitCode::Blocked as i32;
    };
    let pool = match tokio::time::timeout(
        command_timeout(command),
        MySqlPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(command_timeout(command))
            .connect(database_url),
    )
    .await
    {
        Ok(Ok(pool)) => pool,
        _ => {
            emit(
                Output::new(command_name, "BLOCKED", "DATABASE_UNREACHABLE").with_identity(&inputs),
            );
            return ExitCode::Blocked as i32;
        }
    };
    reconcile_after_uncertainty(
        &pool,
        &inputs,
        &permit,
        command_name,
        command_timeout(command),
    )
    .await
}

fn command_timeout(command: &Command) -> Duration {
    Duration::from_secs(command.timeout_seconds)
}

fn command_name(kind: CommandKind) -> &'static str {
    match kind {
        CommandKind::Preflight => "preflight",
        CommandKind::Prepare => "prepare",
        CommandKind::Apply => "apply",
        CommandKind::Reconcile => "reconcile",
    }
}

fn is_unknown_db_commit(error: &PolicyError) -> bool {
    matches!(error, PolicyError::Repository(message) if message.contains("UNKNOWN source bootstrap DB COMMIT"))
}

fn authority_error_reason(error: &AuthorityClientError) -> &'static str {
    match error {
        AuthorityClientError::UnknownOutcome { .. } => {
            "AUTHORITY_OUTCOME_UNKNOWN_RECONCILE_REQUIRED"
        }
        AuthorityClientError::Rejected { .. } => "AUTHORITY_REJECTED",
        AuthorityClientError::InsecureEndpoint => "AUTHORITY_ENDPOINT_INSECURE",
        AuthorityClientError::Attestation(_) => "AUTHORITY_ATTESTATION_FAILED",
        AuthorityClientError::Protocol(_) | AuthorityClientError::ProtocolError(_) => {
            "AUTHORITY_PROTOCOL_INVALID"
        }
        AuthorityClientError::Transport(_) => "AUTHORITY_TRANSPORT_FAILED",
    }
}

impl Output {
    fn with_permit(mut self, permit: &VerifiedSourceBootstrapPermit) -> Self {
        self.operation_id = Some(permit.operation_id().to_owned());
        self.ticket_digest = Some(permit.ticket_digest().to_owned());
        self
    }
}

fn emit(output: Output) {
    // Serialization is infallible for this closed output shape. Keep stdout
    // exclusive: callers consume exactly one machine-readable evidence line.
    if let Ok(line) = serde_json::to_string(&json!(output)) {
        println!("{line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(command: &str) -> Vec<String> {
        vec![
            command.to_owned(),
            "--ticket".to_owned(),
            "/protected/ticket.json".to_owned(),
            "--ca".to_owned(),
            "/protected/ca.pem".to_owned(),
            "--identity".to_owned(),
            "/protected/client.pem".to_owned(),
        ]
    }

    #[test]
    fn local_input_errors_remain_blocked_before_validation_starts() {
        let failure = ClassifiedFailure::blocked("REQUIRED_ENV_MISSING");
        assert_eq!(failure.class, FailureClass::Blocked);
        assert_eq!(failure.status(), "BLOCKED");
        assert_eq!(failure.exit_code(), ExitCode::Blocked);
        assert_eq!(failure.reason, "REQUIRED_ENV_MISSING");
    }

    #[test]
    fn preflight_authority_errors_are_typed_and_redacted() {
        let secret = "mysql://user:password@db.example.invalid/app?token=secret-token";
        let cases = [
            (
                AuthorityClientError::UnknownOutcome {
                    operation_hint: secret.to_owned(),
                },
                FailureClass::Unknown,
                "AUTHORITY_OUTCOME_UNKNOWN_RECONCILE_REQUIRED",
                ExitCode::Unknown,
            ),
            (
                AuthorityClientError::Rejected {
                    code: "INTERNAL".to_owned(),
                    message: secret.to_owned(),
                },
                FailureClass::Failed,
                "AUTHORITY_TICKET_REJECTED",
                ExitCode::Failed,
            ),
            (
                AuthorityClientError::InsecureEndpoint,
                FailureClass::Blocked,
                "AUTHORITY_ENDPOINT_INSECURE",
                ExitCode::Blocked,
            ),
            (
                AuthorityClientError::Attestation(secret.to_owned()),
                FailureClass::Failed,
                "AUTHORITY_ATTESTATION_FAILED",
                ExitCode::Failed,
            ),
            (
                AuthorityClientError::Protocol(secret.to_owned()),
                FailureClass::Failed,
                "AUTHORITY_TICKET_INVALID",
                ExitCode::Failed,
            ),
            (
                AuthorityClientError::ProtocolError(
                    astral_types::AuthorityProtocolError::NotLeader,
                ),
                FailureClass::Failed,
                "AUTHORITY_TICKET_INVALID",
                ExitCode::Failed,
            ),
            (
                AuthorityClientError::Transport(secret.to_owned()),
                FailureClass::Failed,
                "AUTHORITY_TRANSPORT_FAILED",
                ExitCode::Failed,
            ),
        ];

        for (error, class, reason, exit_code) in cases {
            let failure = classify_preflight_authority_error(error);
            assert_eq!(failure.class, class);
            assert_eq!(failure.reason, reason);
            assert_eq!(failure.exit_code(), exit_code);
            assert_eq!(
                failure.status(),
                if class == FailureClass::Unknown {
                    "UNKNOWN"
                } else if class == FailureClass::Blocked {
                    "BLOCKED"
                } else {
                    "FAILED"
                }
            );
            assert!(!failure.reason.contains("password"));
            assert!(!failure.reason.contains("secret-token"));
            assert!(!failure.reason.contains("db.example.invalid"));
        }
    }

    #[test]
    fn source_preflight_and_prepare_errors_have_safe_structured_classes() {
        let secret = "DATABASE_URL=mysql://user:password@db.example.invalid/app";
        let source_cases = [
            (
                PolicyError::InvalidContext(secret.to_owned()),
                "SOURCE_TARGET_PREFLIGHT_INVALID",
            ),
            (
                PolicyError::Repository(secret.to_owned()),
                "SOURCE_TARGET_PREFLIGHT_FAILED",
            ),
            (
                PolicyError::CircuitBreakerOpen,
                "SOURCE_TARGET_PREFLIGHT_CIRCUIT_OPEN",
            ),
            (
                PolicyError::Evaluation(secret.to_owned()),
                "SOURCE_TARGET_PREFLIGHT_EVALUATION_FAILED",
            ),
            (
                PolicyError::NotEligible(secret.to_owned()),
                "SOURCE_TARGET_PREFLIGHT_NOT_ELIGIBLE",
            ),
        ];
        for (error, reason) in source_cases {
            let failure = classify_source_preflight_error(error);
            assert_eq!(failure.class, FailureClass::Failed);
            assert_eq!(failure.status(), "FAILED");
            assert_eq!(failure.exit_code(), ExitCode::Failed);
            assert_eq!(failure.reason, reason);
            assert!(!failure.reason.contains("password"));
            assert!(!failure.reason.contains("db.example.invalid"));
        }

        let prepare_unknown = classify_prepare_error(PolicyError::Repository(secret.to_owned()));
        assert_eq!(prepare_unknown.class, FailureClass::Unknown);
        assert_eq!(prepare_unknown.status(), "UNKNOWN");
        assert_eq!(prepare_unknown.exit_code(), ExitCode::Unknown);
        assert_eq!(
            prepare_unknown.reason,
            "AUTHORITY_PERMIT_OUTCOME_UNKNOWN_RECONCILE_REQUIRED"
        );
        assert!(!prepare_unknown.reason.contains("password"));

        let prepare_invalid = classify_prepare_error(PolicyError::InvalidContext(secret.into()));
        assert_eq!(prepare_invalid.class, FailureClass::Failed);
        assert_eq!(prepare_invalid.status(), "FAILED");
        assert_eq!(prepare_invalid.exit_code(), ExitCode::Failed);
        assert_eq!(prepare_invalid.reason, "AUTHORITY_PERMIT_INVALID");
    }

    #[test]
    fn parser_requires_apply_actor() {
        assert_eq!(parse_args(&args("apply")), Err("ACTOR_ID_REQUIRED"));
    }

    #[test]
    fn parser_accepts_read_only_commands_without_actor() {
        assert_eq!(
            parse_args(&args("preflight")).unwrap().kind,
            CommandKind::Preflight
        );
        assert_eq!(
            parse_args(&args("prepare")).unwrap().kind,
            CommandKind::Prepare
        );
        assert_eq!(
            parse_args(&args("reconcile")).unwrap().kind,
            CommandKind::Reconcile
        );
    }

    #[test]
    fn prepare_requires_a_valid_database_url_before_authority_prepare() {
        assert!(command_requires_database(CommandKind::Prepare));
        assert_eq!(
            database_url_for_command(CommandKind::Prepare, None),
            Err("REQUIRED_ENV_MISSING")
        );
        assert_eq!(
            database_url_for_command(CommandKind::Prepare, Some("https://authority.invalid")),
            Err("DATABASE_URL_INVALID")
        );
        assert_eq!(
            database_url_for_command(CommandKind::Prepare, Some(" mysql://db/app ")),
            Ok(Some("mysql://db/app".to_owned()))
        );

        let failure = ClassifiedFailure::blocked(
            database_url_for_command(CommandKind::Prepare, None).unwrap_err(),
        );
        assert_eq!(failure.status(), "BLOCKED");
        assert_eq!(failure.exit_code(), ExitCode::Blocked);
    }

    #[test]
    fn database_connect_and_schema_failures_are_not_blocked_or_unknown() {
        for (failure, reason) in [
            (
                DatabasePreflightFailure::ConnectTimedOut,
                "DATABASE_CONNECT_TIMED_OUT",
            ),
            (
                DatabasePreflightFailure::ConnectFailed,
                "DATABASE_CONNECT_FAILED",
            ),
            (
                DatabasePreflightFailure::SchemaContractInvalid,
                "SCHEMA_CONTRACT_INVALID",
            ),
            (
                DatabasePreflightFailure::ReadOnlyTimedOut,
                "READ_ONLY_PREFLIGHT_TIMED_OUT",
            ),
        ] {
            let classified = classify_database_preflight_failure(failure);
            assert_eq!(classified.class, FailureClass::Failed);
            assert_eq!(classified.status(), "FAILED");
            assert_eq!(classified.exit_code(), ExitCode::Failed);
            assert_eq!(classified.reason, reason);
        }
    }

    #[test]
    fn unknown_source_commit_is_reconcile_only_and_never_a_source_replay() {
        let error =
            PolicyError::Repository("UNKNOWN source bootstrap DB COMMIT for operation op".into());
        assert!(is_unknown_db_commit(&error));
        assert_eq!(
            reconciliation_decision(None, None, false),
            ReconciliationDecision::Unknown
        );
        assert_ne!(
            reconciliation_decision(None, None, false),
            ReconciliationDecision::Finalize
        );
        assert_ne!(
            reconciliation_decision(None, Some(&completion()), true),
            ReconciliationDecision::Finalize
        );
    }

    #[test]
    fn parser_rejects_unbounded_paths_and_unknown_options() {
        let mut long = args("preflight");
        long[2] = "x".repeat(MAX_PATH_BYTES + 1);
        assert_eq!(parse_args(&long), Err("PATH_INVALID"));
        let mut unknown = args("preflight");
        unknown.push("--secret".to_owned());
        unknown.push("value".to_owned());
        assert_eq!(parse_args(&unknown), Err("OPTION_INVALID"));
    }

    #[test]
    fn parser_rejects_duplicate_options() {
        let mut duplicate = args("reconcile");
        duplicate.extend(["--ticket".to_owned(), "/other/ticket.json".to_owned()]);
        assert_eq!(parse_args(&duplicate), Err("OPTION_DUPLICATED"));
    }

    fn completion() -> AuthoritySourceBootstrapCompletion {
        AuthoritySourceBootstrapCompletion {
            reservation_id: "reservation-1".into(),
            operation_id: "operation-1".into(),
            event_id: "event-1".into(),
            ticket_digest: "1".repeat(64),
            source_payload_digest: "2".repeat(64),
            before_image_digest: "3".repeat(64),
            source_commit_digest: "4".repeat(64),
            after_image_digest: "5".repeat(64),
            source_outcome_digest: "6".repeat(64),
            staged_evidence_digest: "7".repeat(64),
            audit_receipt_digest: "8".repeat(64),
            committed_at: 1_793_000_000,
        }
    }

    #[test]
    fn reconciliation_requires_exact_durable_completion() {
        let source = completion();
        assert_eq!(
            reconciliation_decision(Some(&source), Some(&source), false),
            ReconciliationDecision::Completed,
        );
        for changed in [
            AuthoritySourceBootstrapCompletion {
                operation_id: "other".into(),
                ..source.clone()
            },
            AuthoritySourceBootstrapCompletion {
                event_id: "other".into(),
                ..source.clone()
            },
            AuthoritySourceBootstrapCompletion {
                source_commit_digest: "9".repeat(64),
                ..source.clone()
            },
            AuthoritySourceBootstrapCompletion {
                audit_receipt_digest: "9".repeat(64),
                ..source.clone()
            },
            AuthoritySourceBootstrapCompletion {
                committed_at: source.committed_at + 1,
                ..source.clone()
            },
        ] {
            assert_eq!(
                reconciliation_decision(Some(&source), Some(&changed), false),
                ReconciliationDecision::Conflict,
            );
        }
    }

    #[test]
    fn reconciliation_only_finalizes_a_proven_source_and_exact_reservation() {
        let source = completion();
        assert_eq!(
            reconciliation_decision(Some(&source), None, true),
            ReconciliationDecision::Finalize
        );
        assert_eq!(
            reconciliation_decision(Some(&source), None, false),
            ReconciliationDecision::Pending
        );
        assert_eq!(
            reconciliation_decision(None, None, true),
            ReconciliationDecision::Unknown
        );
        assert_eq!(
            reconciliation_decision(None, Some(&source), true),
            ReconciliationDecision::Unknown
        );
        let invalid = AuthoritySourceBootstrapCompletion {
            source_commit_digest: String::new(),
            ..source
        };
        assert_ne!(
            reconciliation_decision(Some(&invalid), None, true),
            ReconciliationDecision::Finalize
        );
        assert_ne!(
            reconciliation_decision(Some(&invalid), Some(&invalid), false),
            ReconciliationDecision::Completed
        );
    }

    #[test]
    fn bounded_file_reader_accepts_the_limit_and_rejects_larger_inputs() {
        struct InputFile(PathBuf);
        impl Drop for InputFile {
            fn drop(&mut self) {
                let _ = fs::remove_file(&self.0);
            }
        }
        let input = InputFile(
            env::temp_dir().join(format!("astral-bootstrap-input-{}", uuid::Uuid::new_v4(),)),
        );
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&input.0)
            .unwrap();
        std::io::Write::write_all(&mut file, b"12345678").unwrap();
        drop(file);
        assert_eq!(
            read_bounded_file(&input.0, 8, "TICKET").unwrap(),
            b"12345678"
        );
        assert_eq!(
            read_bounded_file(&input.0, 7, "TICKET"),
            Err("INPUT_FILE_TOO_LARGE_OR_NOT_FILE"),
        );
        assert!(read_bounded_file(input.0.parent().unwrap(), 8, "TICKET").is_err());
    }

    #[test]
    fn output_never_contains_completion_as_readiness() {
        let output = Output::new("apply", "COMPLETED", "SOURCE_AND_AUTHORITY_COMPLETED");
        assert_eq!(output.certificate_publication, "NOT_PROVEN");
        assert_eq!(output.readiness, "NOT_PROVEN");
        assert!(!output.replayed);
        assert!(!output.lease_aborted);
    }
}
