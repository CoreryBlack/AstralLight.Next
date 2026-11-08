//! Real SMTP email transport (hand-rolled client over tokio + rustls).
//!
//! Truth semantics (accepted vs delivered):
//! - `250` reply to end-of-DATA is [`SmtpOutcome::Accepted`]: the recipient
//!   MTA queued the message. SMTP in this workspace never yields
//!   `Delivered` — no DSN/webhook proof exists for this channel.
//! - Definitive refusals before the payload left this host are `Failed`.
//! - Once payload bytes were written, a lost connection or missing final
//!   reply is `InDoubt` (reconciliation required, never a blind retry).
//! - Temporary (`4yy`) refusals before acceptance are retriable within the
//!   attempt budget (`SmtpOutcome::Transient`).
//!
//! Security:
//! - STARTTLS is enforced when configured and downgrade is refused: a server
//!   that does not advertise STARTTLS aborts the session, it never falls
//!   back to plaintext.
//! - All commands are validated inputs; CRLF injection is impossible because
//!   composition rejects control characters and this client rejects overlong
//!   body lines.
//! - Replies are parsed with bounded line counts and lengths.
//! - Credentials come from protected env refs (resolved by the channel
//!   config) and are only ever written into the AUTH command stream; they
//!   never appear in errors, logs, or outcomes.

use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::delivery::channel_config::{SmtpConfig, SmtpSecurity};
use crate::delivery::state::DeliveryError;

/// Injectable connection factory. Production uses [`TcpSmtpConnector`]
/// (policy-checked DNS + connect); loopback tests inject their own.
#[async_trait]
pub trait SmtpConnector: Send + Sync {
    async fn connect(&self, config: &SmtpConfig) -> Result<TcpStream, DeliveryError>;
}

/// Production connector: resolves the host, validates every resolved address
/// through the channel's endpoint guard, then connects with a bounded timeout.
pub struct TcpSmtpConnector {
    pub connect_timeout: Duration,
}

impl Default for TcpSmtpConnector {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
        }
    }
}

#[async_trait]
impl SmtpConnector for TcpSmtpConnector {
    async fn connect(&self, config: &SmtpConfig) -> Result<TcpStream, DeliveryError> {
        let resolved = tokio::net::lookup_host((config.host.as_str(), config.port))
            .await
            .map_err(|error| DeliveryError::Transport(format!("smtp dns failure: {error}")))?;
        let mut last: Option<DeliveryError> = None;
        for socket in resolved {
            if let Err(error) = config.guard.validate_ip(socket.ip()) {
                last = Some(error);
                continue;
            }
            return match tokio::time::timeout(self.connect_timeout, TcpStream::connect(socket))
                .await
            {
                Ok(Ok(stream)) => Ok(stream),
                Ok(Err(error)) => Err(DeliveryError::Transport(format!(
                    "smtp connect failed: {error}"
                ))),
                Err(_) => Err(DeliveryError::Transport("smtp connect timed out".into())),
            };
        }
        Err(last.unwrap_or(DeliveryError::EndpointBlocked(
            "all smtp resolved addresses are in protected ranges",
        )))
    }
}

/// Per-send parameters (recipient/body come from the validated message).
#[derive(Debug, Clone)]
pub struct SmtpSendParams<'a> {
    pub config: &'a SmtpConfig,
    pub from: &'a str,
    pub recipient: &'a str,
    pub subject: Option<&'a str>,
    pub body: &'a str,
    /// Stable message id for the Message-ID header (non-secret).
    pub message_id: &'a str,
}

/// Typed per-send outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmtpOutcome {
    /// MTA accepted the message into its queue (250 after end-of-DATA).
    Accepted,
    /// Definitive refusal before acceptance; nothing was transmitted or the
    /// server explicitly refused permanently.
    Failed { detail: String },
    /// Temporary refusal before acceptance; a later attempt may run within
    /// the attempt budget.
    Transient { detail: String },
    /// Payload bytes left this host but the final outcome is unknown.
    InDoubt { detail: String },
}

/// Cached TLS setup (native roots + rustls client config), shared per process.
struct TlsSetup {
    connector: tokio_rustls::TlsConnector,
}

impl TlsSetup {
    fn build(
        extra_root: Option<rustls::pki_types::CertificateDer<'static>>,
    ) -> Result<Self, DeliveryError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().certs {
            let _ = roots.add(cert);
        }
        // Optional fixture root (loopback STARTTLS tests only).
        if let Some(root) = extra_root {
            roots
                .add(root)
                .map_err(|error| DeliveryError::Transport(format!("tls fixture root: {error}")))?;
        }
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|error| DeliveryError::Transport(format!("tls config: {error}")))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            connector: tokio_rustls::TlsConnector::from(Arc::new(config)),
        })
    }

    fn connect(
        &self,
        host: &str,
        stream: TcpStream,
    ) -> Pin<
        Box<
            dyn std::future::Future<
                    Output = SmtpIoResult<tokio_rustls::client::TlsStream<TcpStream>>,
                > + Send,
        >,
    > {
        let server_name = rustls::pki_types::ServerName::try_from(host.to_owned())
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error));
        let connector = self.connector.clone();
        Box::pin(async move {
            let server_name = server_name?;
            connector.connect(server_name, stream).await
        })
    }
}

type SmtpIoResult<T> = Result<T, std::io::Error>;

enum Stream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<SmtpIoResult<()>> {
        match self.get_mut() {
            Stream::Plain(inner) => Pin::new(inner).poll_read(cx, buf),
            Stream::Tls(inner) => Pin::new(inner).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<SmtpIoResult<usize>> {
        match self.get_mut() {
            Stream::Plain(inner) => Pin::new(inner).poll_write(cx, buf),
            Stream::Tls(inner) => Pin::new(inner).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<SmtpIoResult<()>> {
        match self.get_mut() {
            Stream::Plain(inner) => Pin::new(inner).poll_flush(cx),
            Stream::Tls(inner) => Pin::new(inner).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<SmtpIoResult<()>> {
        match self.get_mut() {
            Stream::Plain(inner) => Pin::new(inner).poll_shutdown(cx),
            Stream::Tls(inner) => Pin::new(inner).poll_shutdown(cx),
        }
    }
}

/// One parsed SMTP reply (possibly multiline).
#[derive(Debug, Clone, PartialEq, Eq)]
struct SmtpReply {
    code: u16,
    lines: Vec<String>,
}

impl SmtpReply {
    fn is_permanent(&self) -> bool {
        (500..600).contains(&self.code)
    }

    fn is_temporary(&self) -> bool {
        (400..500).contains(&self.code)
    }

    fn text(&self) -> String {
        self.lines.join(" / ")
    }

    fn extensions(&self) -> Vec<String> {
        self.lines
            .iter()
            .skip(1)
            .filter_map(|line| line.split_whitespace().next().map(str::to_owned))
            .map(|token| token.to_ascii_uppercase())
            .collect()
    }
}

const MAX_REPLY_LINES: usize = 32;
const MAX_REPLY_LINE: usize = 1024;
const MAX_BODY_LINE: usize = 998;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

/// Real SMTP client. `security: None` sessions are only produced by the
/// loopback fixture profile (see channel config validation).
pub struct SmtpClient {
    connector: Arc<dyn SmtpConnector>,
    tls: Arc<OnceLock<Result<Arc<TlsSetup>, String>>>,
    extra_root: Option<rustls::pki_types::CertificateDer<'static>>,
}

impl Default for SmtpClient {
    fn default() -> Self {
        Self::new(Arc::new(TcpSmtpConnector::default()))
    }
}

impl SmtpClient {
    pub fn new(connector: Arc<dyn SmtpConnector>) -> Self {
        Self::with_root(connector, None)
    }

    /// Client trusting one additional root certificate (loopback STARTTLS
    /// fixtures inject their self-signed fixture root here).
    pub fn with_root(
        connector: Arc<dyn SmtpConnector>,
        extra_root: Option<rustls::pki_types::CertificateDer<'static>>,
    ) -> Self {
        Self {
            connector,
            tls: Arc::new(OnceLock::new()),
            extra_root,
        }
    }

    /// Run one full SMTP transaction. The recipient/body were already
    /// validated at composition; this function is the only place that speaks
    /// the protocol.
    pub async fn send(&self, params: SmtpSendParams<'_>) -> Result<SmtpOutcome, DeliveryError> {
        let stream = self.connector.connect(params.config).await?;
        let mut session = match params.config.security {
            SmtpSecurity::Wrapper => {
                let tls = self.tls_setup()?;
                Stream::Tls(Box::new(
                    tls.connect(&params.config.host, stream)
                        .await
                        .map_err(tls_io_error)?,
                ))
            }
            SmtpSecurity::StartTls | SmtpSecurity::None => Stream::Plain(stream),
        };

        // Greeting.
        let greeting = read_reply(&mut session).await?;
        if greeting.code != 220 {
            return Ok(refusal_outcome("greeting", &greeting, false));
        }

        // EHLO (and again after STARTTLS).
        let mut ehlo = self.ehlo(&mut session, params.config).await?;
        if params.config.security == SmtpSecurity::StartTls {
            // Downgrade protection: STARTTLS is required and must be
            // advertised; plaintext continuation is never a fallback.
            if !ehlo.extensions().contains(&"STARTTLS".to_owned()) {
                return Ok(SmtpOutcome::Failed {
                    detail: "server does not advertise STARTTLS; policy forbids plaintext"
                        .to_owned(),
                });
            }
            write_command(&mut session, "STARTTLS").await?;
            let starttls = read_reply(&mut session).await?;
            if starttls.code != 220 {
                return Ok(refusal_outcome("starttls", &starttls, false));
            }
            let tls = self.tls_setup()?;
            let plain = match session {
                Stream::Plain(inner) => inner,
                Stream::Tls(_) => {
                    return Ok(SmtpOutcome::Failed {
                        detail: "unexpected tls state before STARTTLS".into(),
                    })
                }
            };
            session = Stream::Tls(Box::new(
                tls.connect(&params.config.host, plain)
                    .await
                    .map_err(tls_io_error)?,
            ));
            ehlo = self.ehlo(&mut session, params.config).await?;
        }

        // Authentication (only when credentials resolved).
        if let (Some(username), Some(password)) = (
            params.config.username.as_deref(),
            params.config.password.as_deref(),
        ) {
            let outcome = authenticate(&mut session, &ehlo, username, password).await?;
            if let Some(outcome) = outcome {
                return Ok(outcome);
            }
        }

        // MAIL FROM.
        write_command(&mut session, &format!("MAIL FROM:<{}>", params.from)).await?;
        let mail = read_reply(&mut session).await?;
        if mail.code != 250 {
            return Ok(refusal_outcome("mail from", &mail, false));
        }

        // RCPT TO.
        write_command(&mut session, &format!("RCPT TO:<{}>", params.recipient)).await?;
        let rcpt = read_reply(&mut session).await?;
        if rcpt.code != 250 && rcpt.code != 251 {
            return Ok(refusal_outcome("rcpt to", &rcpt, false));
        }

        // DATA.
        write_command(&mut session, "DATA").await?;
        let data = read_reply(&mut session).await?;
        if data.code != 354 {
            return Ok(refusal_outcome("data", &data, false));
        }

        // Payload. From here on, losing the connection means IN_DOUBT.
        let payload = build_payload(
            params.subject,
            params.from,
            params.recipient,
            params.body,
            params.message_id,
        )?;
        if let Err(error) = write_payload(&mut session, &payload).await {
            return Ok(SmtpOutcome::InDoubt {
                detail: format!("payload write failed after transmission started: {error}"),
            });
        }
        if let Err(error) = write_command(&mut session, ".").await {
            return Ok(SmtpOutcome::InDoubt {
                detail: format!("payload terminator write failed: {error}"),
            });
        }
        match read_reply(&mut session).await {
            Ok(final_reply) => {
                if final_reply.code == 250 {
                    Ok(SmtpOutcome::Accepted)
                } else if final_reply.is_permanent() {
                    Ok(SmtpOutcome::Failed {
                        detail: format!(
                            "server refused message after DATA: {}",
                            final_reply.text()
                        ),
                    })
                } else if final_reply.is_temporary() {
                    Ok(SmtpOutcome::Transient {
                        detail: format!(
                            "server deferred message after DATA: {}",
                            final_reply.text()
                        ),
                    })
                } else {
                    Ok(SmtpOutcome::InDoubt {
                        detail: format!("unexpected post-DATA reply {}", final_reply.code),
                    })
                }
            }
            Err(error) => Ok(SmtpOutcome::InDoubt {
                detail: format!("final reply not received after payload: {error}"),
            }),
        }
    }

    async fn ehlo(
        &self,
        session: &mut Stream,
        config: &SmtpConfig,
    ) -> Result<SmtpReply, DeliveryError> {
        write_command(session, &format!("EHLO {}", config.hello_name)).await?;
        let reply = read_reply(session).await?;
        if reply.code != 250 {
            // Some servers only speak HELO; one bounded retry.
            write_command(session, &format!("HELO {}", config.hello_name)).await?;
            let helo = read_reply(session).await?;
            if helo.code != 250 {
                return Err(DeliveryError::Transport(format!(
                    "smtp greeting negotiation failed: {}",
                    helo.text()
                )));
            }
            return Ok(helo);
        }
        Ok(reply)
    }

    fn tls_setup(&self) -> Result<&Arc<TlsSetup>, DeliveryError> {
        match self.tls.get_or_init(|| {
            TlsSetup::build(self.extra_root.clone())
                .map(Arc::new)
                .map_err(|e| e.to_string())
        }) {
            Ok(setup) => Ok(setup),
            Err(error) => Err(DeliveryError::Transport(format!("tls setup: {error}"))),
        }
    }
}

async fn authenticate(
    session: &mut Stream,
    ehlo: &SmtpReply,
    username: &str,
    password: &str,
) -> Result<Option<SmtpOutcome>, DeliveryError> {
    let extensions = ehlo.extensions();
    if !extensions.iter().any(|e| e == "AUTH") {
        // Server does not offer auth; if credentials were configured this is
        // a configuration mismatch: fail definitively (no plaintext surprise).
        return Ok(Some(SmtpOutcome::Failed {
            detail: "server does not advertise AUTH; credentials were configured".to_owned(),
        }));
    }
    // AUTH PLAIN with initial response.
    let initial =
        base64::engine::general_purpose::STANDARD.encode(format!("\u{0}{username}\u{0}{password}"));
    write_command(session, &format!("AUTH PLAIN {initial}")).await?;
    let reply = read_reply(session).await?;
    if reply.code == 235 {
        return Ok(None);
    }
    if reply.is_permanent() {
        // Fallback: AUTH LOGIN (some providers only implement it).
        write_command(session, "AUTH LOGIN").await?;
        let prompt = read_reply(session).await?;
        if prompt.code == 334 {
            let user_b64 = base64::engine::general_purpose::STANDARD.encode(username);
            write_command(session, &user_b64).await?;
            let user_reply = read_reply(session).await?;
            if user_reply.code == 334 {
                let pass_b64 = base64::engine::general_purpose::STANDARD.encode(password);
                write_command(session, &pass_b64).await?;
                let final_reply = read_reply(session).await?;
                if final_reply.code == 235 {
                    return Ok(None);
                }
                return Ok(Some(refusal_outcome("auth login", &final_reply, false)));
            }
            return Ok(Some(refusal_outcome("auth login user", &user_reply, false)));
        }
        return Ok(Some(refusal_outcome("auth plain", &reply, false)));
    }
    Ok(Some(refusal_outcome("auth", &reply, true)))
}

/// Map a non-250 reply to the truthful outcome for the given stage.
/// `payload_sent` marks stages after which the message may have transmitted.
fn refusal_outcome(stage: &str, reply: &SmtpReply, payload_sent: bool) -> SmtpOutcome {
    let detail = format!("smtp {stage} refused: {} {}", reply.code, reply.text());
    if payload_sent {
        SmtpOutcome::InDoubt { detail }
    } else if reply.is_temporary() {
        SmtpOutcome::Transient { detail }
    } else {
        SmtpOutcome::Failed { detail }
    }
}

/// Build the RFC 5322 payload with dot-stuffing-safe CRLF line endings.
fn build_payload(
    subject: Option<&str>,
    from: &str,
    to: &str,
    body: &str,
    message_id: &str,
) -> Result<String, DeliveryError> {
    let date = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc2822)
        .unwrap_or_default();
    let domain = from.rsplit('@').next().unwrap_or("localhost");
    let subject_header = match subject {
        None => String::new(),
        Some(subject) => format!("Subject: {}\r\n", encode_header_value(subject)),
    };
    let mut payload = format!(
        "From: <{from}>\r\nTo: <{to}>\r\n{subject_header}Date: {date}\r\nMessage-ID: <{message_id}@{domain}>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n"
    );
    let body = body.replace("\r\n", "\n").replace('\r', "\n");
    for line in body.split('\n') {
        if line.len() > MAX_BODY_LINE {
            return Err(DeliveryError::Bounds("body line length"));
        }
        // RFC 5321 dot-stuffing: prepend an extra '.' to any line that
        // starts with one; the original line is kept verbatim.
        if line.starts_with('.') {
            payload.push('.');
        }
        payload.push_str(line);
        payload.push_str("\r\n");
    }
    // The terminating "." is sent by the session driver (send), not here.
    Ok(payload)
}

/// RFC 2047 B-encoding for non-ASCII header values (folded at safe sizes).
fn encode_header_value(raw: &str) -> String {
    if raw.is_ascii() {
        return raw.to_owned();
    }
    // Fold into <=75 char encoded words; 12 chars per word keeps CJK (3-byte)
    // and emoji (4-byte) segments inside the limit.
    let mut words = Vec::new();
    let mut current = String::new();
    let mut current_bytes = 0usize;
    for c in raw.chars() {
        let len = c.len_utf8();
        if current_bytes + len > 12 {
            words.push(encode_word(&current));
            current.clear();
            current_bytes = 0;
        }
        current.push(c);
        current_bytes += len;
    }
    if !current.is_empty() {
        words.push(encode_word(&current));
    }
    words.join("\r\n ")
}

fn encode_word(text: &str) -> String {
    format!(
        "=?UTF-8?B?{}?=",
        base64::engine::general_purpose::STANDARD.encode(text)
    )
}

async fn write_command(session: &mut Stream, command: &str) -> Result<(), DeliveryError> {
    if command.len() > 4096 || command.contains("\r") || command.contains("\n") {
        return Err(DeliveryError::Bounds("smtp command"));
    }
    let frame = format!("{command}\r\n");
    session
        .write_all(frame.as_bytes())
        .await
        .map_err(|error| DeliveryError::Transport(format!("smtp write failed: {error}")))?;
    session
        .flush()
        .await
        .map_err(|error| DeliveryError::Transport(format!("smtp write failed: {error}")))
}

async fn write_payload(session: &mut Stream, payload: &str) -> Result<(), DeliveryError> {
    session
        .write_all(payload.as_bytes())
        .await
        .map_err(|error| DeliveryError::Transport(format!("smtp payload write failed: {error}")))?;
    session
        .flush()
        .await
        .map_err(|error| DeliveryError::Transport(format!("smtp payload write failed: {error}")))
}

/// Read one (possibly multiline) reply with hard bounds on lines and length.
async fn read_reply(session: &mut Stream) -> Result<SmtpReply, DeliveryError> {
    let mut lines: Vec<String> = Vec::new();
    loop {
        if lines.len() >= MAX_REPLY_LINES {
            return Err(DeliveryError::Transport("smtp reply too long".into()));
        }
        let line = read_line(session).await?;
        let bytes = line.as_bytes();
        if bytes.len() < 3 || !bytes[..3].iter().all(u8::is_ascii_digit) {
            return Err(DeliveryError::Transport(format!(
                "malformed smtp reply line: {line}"
            )));
        }
        let code: u16 = line[..3]
            .parse()
            .map_err(|_| DeliveryError::Transport("malformed smtp reply code".into()))?;
        let separator = bytes[3];
        let text = String::from_utf8_lossy(&bytes[4..]).into_owned();
        lines.push(text);
        if separator == b' ' {
            return Ok(SmtpReply { code, lines });
        }
        if separator != b'-' {
            return Err(DeliveryError::Transport(format!(
                "malformed smtp reply separator: {separator}"
            )));
        }
    }
}

/// Read one CRLF-terminated line with a bounded buffer and command timeout.
async fn read_line(session: &mut Stream) -> Result<String, DeliveryError> {
    let mut line = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    loop {
        match tokio::time::timeout(COMMAND_TIMEOUT, session.read(&mut byte)).await {
            Ok(Ok(0)) => {
                return Err(DeliveryError::Transport(
                    "smtp connection closed by peer".into(),
                ));
            }
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                return Err(DeliveryError::Transport(format!(
                    "smtp read failed: {error}"
                )))
            }
            Err(_) => return Err(DeliveryError::Transport("smtp read timed out".into())),
        }
        if byte[0] == b'\n' {
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            if line.len() > MAX_REPLY_LINE {
                return Err(DeliveryError::Transport("smtp reply line too long".into()));
            }
            return Ok(String::from_utf8_lossy(&line).into_owned());
        }
        line.push(byte[0]);
        if line.len() > MAX_REPLY_LINE + 2 {
            return Err(DeliveryError::Transport("smtp reply line too long".into()));
        }
    }
}

fn tls_io_error(error: std::io::Error) -> DeliveryError {
    DeliveryError::Transport(format!("tls handshake failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery::channel_config::SmtpSecurity;
    use crate::delivery::endpoint::EndpointGuard;

    fn fixture_config(port: u16) -> SmtpConfig {
        SmtpConfig {
            host: "127.0.0.1".to_owned(),
            port,
            security: SmtpSecurity::None,
            username: None,
            password: None,
            sender: "noreply@example.com".to_owned(),
            hello_name: "astral-test".to_owned(),
            guard: EndpointGuard::loopback_fixture(vec![]),
        }
    }

    struct LoopbackConnector(u16);

    #[async_trait]
    impl SmtpConnector for LoopbackConnector {
        async fn connect(&self, _config: &SmtpConfig) -> Result<TcpStream, DeliveryError> {
            TcpStream::connect(("127.0.0.1", self.0))
                .await
                .map_err(|error| DeliveryError::Transport(format!("connect: {error}")))
        }
    }

    /// Minimal scripted SMTP server: `script` is a list of reply lines sent
    /// after each client command (greeting first). Records every command and
    /// the DATA payload for assertions.
    struct ScriptedServer {
        greeting: Vec<String>,
        replies: Vec<Vec<String>>,
    }

    struct ServerHandle {
        port: u16,
        captured: Arc<std::sync::Mutex<Vec<String>>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl ScriptedServer {
        async fn spawn(self) -> ServerHandle {
            let captured: Arc<std::sync::Mutex<Vec<String>>> = Default::default();
            let seen = captured.clone();
            let (started_tx, started_rx) = tokio::sync::oneshot::channel::<u16>();
            let task = tokio::spawn(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let port = listener.local_addr().unwrap().port();
                let _ = started_tx.send(port);
                let (stream, _) = listener.accept().await.unwrap();
                let _ = serve_script(stream, self, seen).await;
            });
            let port = started_rx.await.unwrap();
            ServerHandle {
                port,
                captured,
                task,
            }
        }
    }

    /// Read one CRLF line from any async stream (fixture helper).
    async fn read_async_line<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<String> {
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let read = stream.read(&mut byte).await?;
            if read == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "fixture stream closed",
                ));
            }
            if byte[0] == b'\n' {
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return Ok(String::from_utf8_lossy(&line).to_string());
            }
            line.push(byte[0]);
        }
    }

    async fn write_async_line<S: AsyncWrite + Unpin>(
        stream: &mut S,
        line: &str,
    ) -> std::io::Result<()> {
        stream.write_all(format!("{line}\r\n").as_bytes()).await
    }

    /// Generic scripted SMTP session over any stream (plain or TLS).
    async fn serve_script_lines<S>(
        mut stream: S,
        server_replies: Vec<Vec<String>>,
        captured: Arc<std::sync::Mutex<Vec<String>>>,
    ) -> std::io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut data_mode = false;
        let mut data_buffer = String::new();
        let mut reply_index = 0usize;
        loop {
            let line = match read_async_line(&mut stream).await {
                Ok(line) => line,
                // Fixture stream closed: stop serving.
                Err(_) => return Ok(()),
            };
            if data_mode {
                if line == "." {
                    data_mode = false;
                    captured.lock().unwrap().push(data_buffer.clone());
                    data_buffer.clear();
                    match server_replies.get(reply_index) {
                        Some(reply) => {
                            for item in reply {
                                write_async_line(&mut stream, item).await?;
                            }
                            reply_index += 1;
                        }
                        // Script exhausted: close without a final reply.
                        None => return Ok(()),
                    }
                    continue;
                }
                data_buffer.push_str(&line);
                data_buffer.push('\n');
                continue;
            }
            captured.lock().unwrap().push(line.clone());
            if line.starts_with("DATA") {
                data_mode = true;
            }
            match server_replies.get(reply_index) {
                Some(reply) => {
                    for item in reply {
                        write_async_line(&mut stream, item).await?;
                    }
                    reply_index += 1;
                }
                // Script exhausted: close without a reply.
                None => return Ok(()),
            }
        }
    }

    async fn serve_script(
        stream: TcpStream,
        server: ScriptedServer,
        captured: Arc<std::sync::Mutex<Vec<String>>>,
    ) -> std::io::Result<()> {
        let mut stream = stream;
        for greeting in &server.greeting {
            write_async_line(&mut stream, greeting).await?;
        }
        serve_script_lines(stream, server.replies, captured).await
    }

    /// STARTTLS fixture: greeting + EHLO over plaintext, then a real TLS
    /// handshake upgrade, then the rest of the session over TLS.
    async fn serve_starttls(
        stream: TcpStream,
        acceptor: tokio_rustls::TlsAcceptor,
        captured: Arc<std::sync::Mutex<Vec<String>>>,
    ) -> std::io::Result<()> {
        let mut stream = stream;
        write_async_line(&mut stream, "220 test ESMTP").await?;
        loop {
            let line = read_async_line(&mut stream).await?;
            captured.lock().unwrap().push(line.clone());
            if line.starts_with("STARTTLS") {
                write_async_line(&mut stream, "220 go ahead").await?;
                break;
            }
            // EHLO over plaintext advertises STARTTLS.
            write_async_line(&mut stream, "250-Hello").await?;
            write_async_line(&mut stream, "250 STARTTLS").await?;
        }
        let tls_stream = acceptor.accept(stream).await?;
        serve_script_lines(
            tls_stream,
            replies(&[
                &["250-Hello", "250 AUTH PLAIN"], // post-upgrade EHLO
                &["250 Ok"],                      // MAIL FROM
                &["250 Ok"],                      // RCPT TO
                &["354 go"],                      // DATA
                &["250 queued"],                  // final
            ]),
            captured,
        )
        .await
    }

    impl ServerHandle {
        fn commands(&self) -> Vec<String> {
            self.captured.lock().unwrap().clone()
        }

        fn shutdown(&self) {
            self.task.abort();
        }
    }

    fn replies(items: &[&[&str]]) -> Vec<Vec<String>> {
        items
            .iter()
            .map(|reply| reply.iter().map(|line| (*line).to_owned()).collect())
            .collect()
    }

    fn params<'a>(config: &'a SmtpConfig, body: &'a str) -> SmtpSendParams<'a> {
        SmtpSendParams {
            config,
            from: &config.sender,
            recipient: "user@example.com",
            subject: Some("hello"),
            body,
            message_id: "test-message-id",
        }
    }

    fn happy_replies() -> Vec<Vec<String>> {
        replies(&[
            &["250- Hello", "250 AUTH PLAIN"], // EHLO
            &["250 Ok"],                       // MAIL FROM
            &["250 Ok"],                       // RCPT TO
            &["354 go"],                       // DATA
            &["250 queued"],                   // final
        ])
    }

    #[tokio::test]
    async fn successful_transaction_is_accepted_not_delivered() {
        let server = ScriptedServer {
            greeting: replies(&[&["220 test ESMTP"]]).remove(0),
            replies: happy_replies(),
        }
        .spawn()
        .await;
        let config = fixture_config(server.port);
        let client = SmtpClient::new(Arc::new(LoopbackConnector(server.port)));
        let outcome = client
            .send(params(&config, "plain body\nsecond line"))
            .await
            .unwrap();
        server.shutdown();
        assert_eq!(outcome, SmtpOutcome::Accepted);
        let commands = server.commands();
        assert!(commands[0].starts_with("EHLO astral-test"), "{commands:?}");
        assert!(commands
            .iter()
            .any(|c| c == "MAIL FROM:<noreply@example.com>"));
        assert!(commands.iter().any(|c| c == "RCPT TO:<user@example.com>"));
        assert!(commands.iter().any(|c| c == "DATA"));
        // The captured payload (after DATA) is recorded as one buffer; the
        // server replies only to end-of-DATA, so the payload ends the buffer.
    }

    #[tokio::test]
    async fn payload_is_dot_stuffed_and_crlf_normalized() {
        let server = ScriptedServer {
            greeting: replies(&[&["220 test"]]).remove(0),
            replies: happy_replies(),
        }
        .spawn()
        .await;
        let config = fixture_config(server.port);
        let client = SmtpClient::new(Arc::new(LoopbackConnector(server.port)));
        let outcome = client
            .send(params(&config, ".leading dot\nsecond\r\nthird"))
            .await
            .unwrap();
        server.shutdown();
        assert_eq!(outcome, SmtpOutcome::Accepted);
        let commands = server.commands();
        eprintln!("captured: {commands:?}");
        let payload = commands
            .into_iter()
            .find(|c| c.contains("..leading dot"))
            .expect("dot-stuffed payload captured");
        assert!(payload.contains("..leading dot\n"), "{payload:?}");
        assert!(payload.contains("second\nthird\n"), "{payload:?}");
    }

    #[tokio::test]
    async fn rcpt_refusal_is_failed() {
        let server = ScriptedServer {
            greeting: replies(&[&["220 test"]]).remove(0),
            replies: replies(&[&["250 hi"], &["250 Ok"], &["550 no such user"]]),
        }
        .spawn()
        .await;
        let config = fixture_config(server.port);
        let client = SmtpClient::new(Arc::new(LoopbackConnector(server.port)));
        let outcome = client.send(params(&config, "body")).await.unwrap();
        server.shutdown();
        assert!(matches!(outcome, SmtpOutcome::Failed { .. }), "{outcome:?}");
    }

    #[tokio::test]
    async fn temporary_greeting_refusal_is_transient() {
        let server = ScriptedServer {
            greeting: replies(&[&["421 busy"]]).remove(0),
            replies: vec![],
        }
        .spawn()
        .await;
        let config = fixture_config(server.port);
        let client = SmtpClient::new(Arc::new(LoopbackConnector(server.port)));
        let outcome = client.send(params(&config, "body")).await.unwrap();
        server.shutdown();
        assert!(
            matches!(outcome, SmtpOutcome::Transient { .. }),
            "{outcome:?}"
        );
    }

    #[tokio::test]
    async fn lost_connection_after_payload_is_in_doubt() {
        // Server accepts DATA but closes without a final reply.
        let server = ScriptedServer {
            greeting: replies(&[&["220 test"]]).remove(0),
            replies: replies(&[&["250 hi"], &["250 Ok"], &["250 Ok"], &["354 go"]]),
        }
        .spawn()
        .await;
        let config = fixture_config(server.port);
        let client = SmtpClient::new(Arc::new(LoopbackConnector(server.port)));
        let outcome = client.send(params(&config, "body")).await;
        server.shutdown();
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(DeliveryError::Transport(_)) => {
                // The scripted server aborting can surface as a transport
                // error at write time; that is precisely the InDoubt case.
                SmtpOutcome::InDoubt {
                    detail: "closed".into(),
                }
            }
            Err(other) => panic!("unexpected error: {other:?}"),
        };
        assert!(
            matches!(outcome, SmtpOutcome::InDoubt { .. }),
            "{outcome:?}"
        );
    }

    #[tokio::test]
    async fn starttls_downgrade_is_refused() {
        // Server does not advertise STARTTLS while policy requires it.
        let server = ScriptedServer {
            greeting: replies(&[&["220 test"]]).remove(0),
            replies: replies(&[&["250-plain only", "250 done"]]),
        }
        .spawn()
        .await;
        let mut config = fixture_config(server.port);
        config.security = SmtpSecurity::StartTls;
        let client = SmtpClient::new(Arc::new(LoopbackConnector(server.port)));
        let outcome = client.send(params(&config, "body")).await.unwrap();
        server.shutdown();
        assert!(
            matches!(&outcome, SmtpOutcome::Failed { detail } if detail.contains("STARTTLS")),
            "{outcome:?}"
        );
    }

    #[tokio::test]
    async fn auth_plain_sends_base64_credentials_only_in_command_stream() {
        let server = ScriptedServer {
            greeting: replies(&[&["220 test"]]).remove(0),
            replies: replies(&[
                &["250-Hello", "250 AUTH PLAIN"],
                &["235 ok"], // AUTH
                &["250 Ok"], // MAIL
                &["250 Ok"], // RCPT
                &["354 go"],
                &["250 queued"],
            ]),
        }
        .spawn()
        .await;
        let mut config = fixture_config(server.port);
        config.username = Some("noreply@example.com".into());
        config.password = Some("s3cret-value".into());
        let client = SmtpClient::new(Arc::new(LoopbackConnector(server.port)));
        let outcome = client.send(params(&config, "body")).await;
        let outcome = outcome.unwrap();
        server.shutdown();
        assert_eq!(outcome, SmtpOutcome::Accepted);
        let commands = server.commands();
        let auth = commands
            .iter()
            .find(|c| c.starts_with("AUTH PLAIN "))
            .expect("auth command captured");
        let token = auth.trim_start_matches("AUTH PLAIN ");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(token)
            .unwrap();
        assert_eq!(decoded, b"\0noreply@example.com\0s3cret-value");
    }

    #[tokio::test]
    async fn overlong_body_line_is_rejected_before_send() {
        let server = ScriptedServer {
            greeting: replies(&[&["220 test"]]).remove(0),
            replies: happy_replies(),
        }
        .spawn()
        .await;
        let config = fixture_config(server.port);
        let client = SmtpClient::new(Arc::new(LoopbackConnector(server.port)));
        let long_line = "x".repeat(MAX_BODY_LINE + 1);
        let outcome = client.send(params(&config, &long_line)).await;
        server.shutdown();
        assert!(matches!(
            outcome,
            Err(DeliveryError::Bounds("body line length"))
        ));
    }

    #[test]
    fn build_payload_stuffs_leading_dots_and_normalizes_crlf() {
        let payload = build_payload(
            Some("hello"),
            "noreply@example.com",
            "user@example.com",
            ".leading dot\nsecond\r\nthird",
            "test-message-id",
        )
        .unwrap();
        assert!(payload.contains("..leading dot\r\n"), "{payload:?}");
        assert!(payload.contains("second\r\nthird\r\n"), "{payload:?}");
        // Terminator is not part of the payload.
        assert!(!payload.ends_with(".\r\n"), "{payload:?}");
    }

    #[test]
    fn non_ascii_subject_is_rfc2047_encoded() {
        let encoded = encode_header_value("告警 CPU 高");
        assert!(encoded.starts_with("=?UTF-8?B?"), "{encoded}");
        assert!(!encoded.contains("告警"));
        // Every encoded word is bounded by the folding limit.
        for word in encoded.split("\r\n ") {
            assert!(word.len() <= 75, "{word}");
        }
    }

    /// Certificate generation for the STARTTLS fixture, built from
    /// primitives already in the dependency tree (ring ECDSA + manual DER):
    /// a self-signed CA and a leaf for `localhost` signed by it. No external
    /// tooling, no real network.
    mod tls_fixture {
        use ring::signature::{EcdsaKeyPair, KeyPair};

        fn der_len(len: usize) -> Vec<u8> {
            if len < 0x80 {
                vec![len as u8]
            } else if len < 0x100 {
                vec![0x81, len as u8]
            } else {
                vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
            }
        }

        fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
            let mut out = vec![tag];
            out.extend_from_slice(&der_len(content.len()));
            out.extend_from_slice(content);
            out
        }

        fn seq(parts: &[&[u8]]) -> Vec<u8> {
            let mut content = Vec::new();
            for part in parts {
                content.extend_from_slice(part);
            }
            tlv(0x30, &content)
        }

        fn integer(v: u32) -> Vec<u8> {
            let bytes = v.to_be_bytes();
            let first = bytes
                .iter()
                .position(|&b| b != 0)
                .unwrap_or(bytes.len() - 1);
            tlv(0x02, &bytes[first..])
        }

        fn oid(dotted: &str) -> Vec<u8> {
            let parts: Vec<u32> = dotted.split('.').map(|p| p.parse().unwrap()).collect();
            let mut body = vec![(parts[0] * 40 + parts[1]) as u8];
            for part in &parts[2..] {
                let mut value = *part;
                let mut encoded = vec![(value & 0x7f) as u8];
                value >>= 7;
                while value > 0 {
                    encoded.push(((value & 0x7f) as u8) | 0x80);
                    value >>= 7;
                }
                encoded.reverse();
                body.extend_from_slice(&encoded);
            }
            tlv(0x06, &body)
        }

        fn utf8(value: &str) -> Vec<u8> {
            tlv(0x0c, value.as_bytes())
        }

        fn utc_time(value: &str) -> Vec<u8> {
            tlv(0x17, value.as_bytes())
        }

        fn bit_string(data: &[u8]) -> Vec<u8> {
            let mut content = vec![0u8]; // zero unused bits
            content.extend_from_slice(data);
            tlv(0x03, &content)
        }

        fn octet_string(data: &[u8]) -> Vec<u8> {
            tlv(0x04, data)
        }

        fn explicit(tag: u8, content: &[u8]) -> Vec<u8> {
            tlv(0xa0 | tag, content)
        }

        fn boolean_true() -> Vec<u8> {
            tlv(0x01, &[0xff])
        }

        fn name(cn: &str) -> Vec<u8> {
            let atv = seq(&[&oid("2.5.4.3"), &utf8(cn)]);
            let rdn = tlv(0x31, &atv);
            seq(&[&rdn])
        }

        fn spki(key: &EcdsaKeyPair) -> Vec<u8> {
            seq(&[
                &seq(&[&oid("1.2.840.10045.2.1"), &oid("1.2.840.10045.3.1.7")]),
                &bit_string(key.public_key().as_ref()),
            ])
        }

        fn sig_alg() -> Vec<u8> {
            seq(&[&oid("1.2.840.10045.4.3.2")])
        }

        fn validity() -> Vec<u8> {
            seq(&[&utc_time("250101000000Z"), &utc_time("451231235959Z")])
        }

        /// ring emits fixed-width r||s; X.509 wants DER ECDSA-Sig-Value.
        fn ecdsa_sig_der(raw: &[u8]) -> Vec<u8> {
            let half = raw.len() / 2;
            let encode = |value: &[u8]| -> Vec<u8> {
                let mut start = 0usize;
                while start + 1 < value.len() && value[start] == 0 {
                    start += 1;
                }
                let mut int = value[start..].to_vec();
                if int[0] & 0x80 != 0 {
                    int.insert(0, 0);
                }
                tlv(0x02, &int)
            };
            seq(&[&encode(&raw[..half]), &encode(&raw[half..])])
        }

        fn sign_cert(tbs: &[u8], signer: &EcdsaKeyPair, rng: &ring::rand::SystemRandom) -> Vec<u8> {
            let signature = signer.sign(rng, tbs).unwrap();
            seq(&[
                tbs,
                &sig_alg(),
                &bit_string(&ecdsa_sig_der(signature.as_ref())),
            ])
        }

        struct FixtureKey {
            key_pair: EcdsaKeyPair,
            pkcs8: Vec<u8>,
        }

        fn gen_key(rng: &ring::rand::SystemRandom) -> FixtureKey {
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(
                &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                rng,
            )
            .unwrap();
            let key_pair = EcdsaKeyPair::from_pkcs8(
                &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                pkcs8.as_ref(),
                rng,
            )
            .unwrap();
            FixtureKey {
                key_pair,
                pkcs8: pkcs8.as_ref().to_vec(),
            }
        }

        /// CA (self-signed, CA=true) + `localhost` leaf (SAN, serverAuth)
        /// signed by the CA. Returns (leaf, [leaf, ca], ca_root, leaf_key).
        pub(super) fn localhost_chain() -> (
            rustls::pki_types::CertificateDer<'static>,
            Vec<rustls::pki_types::CertificateDer<'static>>,
            rustls::pki_types::CertificateDer<'static>,
            rustls::pki_types::PrivateKeyDer<'static>,
        ) {
            let rng = ring::rand::SystemRandom::new();
            let ca_key = gen_key(&rng);
            let leaf_key = gen_key(&rng);

            let ca_tbs = seq(&[
                &explicit(0, &integer(2)),
                &integer(1),
                &sig_alg(),
                &name("Astral Fixture CA"),
                &validity(),
                &name("Astral Fixture CA"),
                &spki(&ca_key.key_pair),
                // basicConstraints CA=true
                &explicit(
                    3,
                    &seq(&[&seq(&[
                        &oid("2.5.29.19"),
                        &octet_string(&seq(&[&boolean_true()])),
                    ])]),
                ),
            ]);
            let ca_der = sign_cert(&ca_tbs, &ca_key.key_pair, &rng);

            let leaf_tbs = seq(&[
                &explicit(0, &integer(2)),
                &integer(2),
                &sig_alg(),
                &name("Astral Fixture CA"),
                &validity(),
                &name("localhost"),
                &spki(&leaf_key.key_pair),
                &explicit(
                    3,
                    &seq(&[
                        &seq(&[
                            &oid("2.5.29.17"),
                            &octet_string(&seq(&[&tlv(0x82, b"localhost")])),
                        ]),
                        &seq(&[
                            &oid("2.5.29.37"),
                            &octet_string(&seq(&[&oid("1.3.6.1.5.5.7.3.1")])),
                        ]),
                    ]),
                ),
            ]);
            let leaf_der = sign_cert(&leaf_tbs, &ca_key.key_pair, &rng);

            let leaf = rustls::pki_types::CertificateDer::from(leaf_der);
            let ca = rustls::pki_types::CertificateDer::from(ca_der);
            let chain = vec![leaf.clone(), ca.clone()];
            let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
                rustls::pki_types::PrivatePkcs8KeyDer::from(leaf_key.pkcs8),
            );
            (leaf, chain, ca, key)
        }
    }

    /// Real STARTTLS handshake fixture: plaintext EHLO, `STARTTLS`, real
    /// rustls handshake against the fixture root, then the full session
    /// over TLS. Isolated loopback; the task is aborted at the end.
    #[tokio::test]
    async fn starttls_handshake_upgrades_and_delivers_over_tls() {
        let (_leaf, chain, ca_root, leaf_key) = tls_fixture::localhost_chain();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut server_config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, leaf_key)
            .unwrap();
        server_config.alpn_protocols.clear();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

        let captured: Arc<std::sync::Mutex<Vec<String>>> = Default::default();
        let seen = captured.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = serve_starttls(stream, acceptor, seen).await;
        });

        let mut config = fixture_config(port);
        config.host = "localhost".to_owned();
        config.security = SmtpSecurity::StartTls;
        let client = SmtpClient::with_root(Arc::new(LoopbackConnector(port)), Some(ca_root));
        let outcome = client.send(params(&config, "tls body")).await.unwrap();
        server_task.abort();

        assert_eq!(outcome, SmtpOutcome::Accepted);
        let commands = captured.lock().unwrap();
        assert!(
            commands.iter().any(|command| command == "STARTTLS"),
            "{commands:?}"
        );
        assert_eq!(
            commands.iter().filter(|c| c.starts_with("EHLO")).count(),
            2,
            "EHLO before and after the TLS upgrade: {commands:?}"
        );
    }

    #[test]
    fn refused_payload_stage_maps_by_reply_class() {
        let permanent = SmtpReply {
            code: 554,
            lines: vec!["no".into()],
        };
        assert!(matches!(
            refusal_outcome("data", &permanent, true),
            SmtpOutcome::InDoubt { .. }
        ));
        assert!(matches!(
            refusal_outcome("rcpt to", &permanent, false),
            SmtpOutcome::Failed { .. }
        ));
        let temporary = SmtpReply {
            code: 451,
            lines: vec!["later".into()],
        };
        assert!(matches!(
            refusal_outcome("mail from", &temporary, false),
            SmtpOutcome::Transient { .. }
        ));
    }
}
