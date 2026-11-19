//! memory—v1: Closed-loop HTTP read/login curve on the composed stress fixture.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::process::Command;
use std::time::Duration;

use anyhow::{ensure, Context, Result};
use reqwest::{Client, RequestBuilder, StatusCode};
use serde_json::{json, Value};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::{timeout, Instant};

use super::{
    login_body, registry_declarations, PhaseQuantile, CARD_ALLOW, CARD_BOB, LOGIN, REGISTRY,
};

const CURVE_ENV: &str = "ASTRAL_MEMORY_V1_LOGIN_CURVE";
const ROUNDS_ENV: &str = "ASTRAL_MEMORY_V1_LOGIN_CURVE_ROUNDS";
const CELL_ENV: &str = "ASTRAL_MEMORY_V1_LOGIN_CURVE_CELL";
const READERS: usize = 4;
const LOGIN_WORKERS: [usize; 4] = [1, 4, 8, 16];
const WINDOW: Duration = Duration::from_secs(1);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const WARMUP_TIMEOUT: Duration = Duration::from_secs(30);
// The composed authority caps live records at 100,000 with a 1,800 s
// lifetime. A fresh child starts empty per cell, and this guard bounds even
// unknown login outcomes to 16 * 2,048 + 17 setup sessions. A hit invalidates
// the cell instead of reporting capped traffic as a login throughput sample.
const LOGIN_ATTEMPTS_PER_WORKER: usize = 2_048;

#[derive(Clone, Copy)]
pub(super) struct Cell {
    round: usize,
    readers: usize,
    logins: usize,
}

impl Cell {
    // memory—v1: Label the worker configuration for comparison across cells.
    fn mode(self) -> &'static str {
        match (self.readers, self.logins) {
            (_, 0) => "read_only",
            (0, _) => "login_only",
            _ => "mixed",
        }
    }
}

/// memory—v1: Opt in to the login matrix with a bounded number of rounds.
pub(super) fn rounds() -> Option<usize> {
    let enabled = std::env::var_os(CURVE_ENV)?;
    assert_eq!(enabled, "1", "{CURVE_ENV} must be 1 when set");
    assert!(
        std::env::var_os("ASTRAL_MEMORY_V1_ALLOW_CURVE").is_none(),
        "the ALLOW and login curve modes must run separately"
    );
    let rounds = std::env::var_os(ROUNDS_ENV);
    Some(match rounds.as_deref().and_then(std::ffi::OsStr::to_str) {
        None if rounds.is_none() => 1,
        Some("1") => 1,
        Some("4") => 4,
        Some("8") => 8,
        _ => panic!("{ROUNDS_ENV} must be 1, 4 or 8"),
    })
}

/// memory—v1: Run cells sequentially in fresh stress children and forward their reports.
pub(super) fn run_matrix(child: &mut Command, rounds: usize) {
    let mut cells = vec![(READERS, 0)];
    for logins in LOGIN_WORKERS {
        cells.extend([(0, logins), (READERS, logins)]);
    }
    for round in 1..=rounds {
        for &(readers, logins) in &cells {
            let output = child
                .env(CELL_ENV, format!("{round}:{readers}:{logins}"))
                .output()
                .expect("start the login curve stress child");
            eprint!("{}", String::from_utf8_lossy(&output.stderr));
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                output.status.success() && stdout.contains("1 passed"),
                "login curve child failed for round {round}, readers {readers}, logins {logins}:\n{stdout}"
            );
        }
        // Alternate the ordering of baseline and load cells in repeated rounds.
        cells.reverse();
    }
}

/// memory—v1: Decode the parent-selected cell before creating the child fixture.
pub(super) fn selected_cell() -> Option<Cell> {
    let rounds = rounds()?;
    let value = std::env::var(CELL_ENV).expect("the stress parent selects a login curve cell");
    let mut fields = value.split(':').map(|n| n.parse::<usize>().unwrap());
    let round = fields.next().unwrap();
    let readers = fields.next().unwrap();
    let logins = fields.next().unwrap();
    assert!(fields.next().is_none());
    assert!((1..=rounds).contains(&round));
    assert!(
        (readers == READERS && logins == 0)
            || ((readers == 0 || readers == READERS) && LOGIN_WORKERS.contains(&logins))
    );
    Some(Cell {
        round,
        readers,
        logins,
    })
}

#[derive(Clone, Copy)]
enum Class {
    Read,
    Login,
}

struct Endpoints {
    login: String,
    registry: String,
    registry_len: usize,
}

impl Endpoints {
    // memory—v1: Send fixture credentials using the same HTTP session route as clients.
    fn login_request(&self, client: &Client, card: [u8; 16]) -> RequestBuilder {
        client.post(&self.login).json(&login_body(card))
    }

    // memory—v1: Reuse the already-issued bearer for registry reads.
    fn read_request(&self, client: &Client, token: &str) -> RequestBuilder {
        client.get(&self.registry).bearer_auth(token)
    }

    // memory—v1: Check the real registry body as well as the warm-up status.
    async fn warm_read(&self, request: RequestBuilder) -> Result<()> {
        let (status, bytes) = exchange(request)
            .await
            .context("warm registry HTTP exchange")?;
        ensure!(status == StatusCode::OK, "warm registry status {status}");
        let body: Value = serde_json::from_slice(bytes.as_ref()).context("warm registry JSON")?;
        ensure!(
            body["data"].as_array().map(Vec::len) == Some(self.registry_len),
            "warm registry returned an unexpected entry count"
        );
        Ok(())
    }

    // memory—v1: Verify that a warm login yields a usable registry bearer.
    async fn warm_login(&self, client: &Client, request: RequestBuilder) -> Result<String> {
        let (status, bytes) = exchange(request)
            .await
            .context("warm login HTTP exchange")?;
        ensure!(status == StatusCode::OK, "warm login status {status}");
        let body: Value = serde_json::from_slice(bytes.as_ref()).context("warm login JSON")?;
        let token = response_token(&body).context("warm login returned an invalid bearer")?;
        self.warm_read(self.read_request(client, token)).await?;
        Ok(token.to_owned())
    }
}

// memory—v1: Give each worker its own HTTP/1 connection pool with no proxy or retries.
fn client() -> Result<Client> {
    Ok(Client::builder()
        .http1_only()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .pool_max_idle_per_host(1)
        .timeout(REQUEST_TIMEOUT)
        .build()?)
}

// memory—v1: Drain the entire response to measure RTT and allow connection reuse.
async fn exchange(request: RequestBuilder) -> reqwest::Result<(StatusCode, impl AsRef<[u8]>)> {
    let response = request.send().await?;
    Ok((response.status(), response.bytes().await?))
}

// memory—v1: Validate the public login response envelope without printing credentials.
fn response_token(body: &Value) -> Option<&str> {
    let data = &body["data"];
    if data["tokenType"].as_str() != Some("Bearer") || data["expiresIn"].as_i64()? <= 0 {
        return None;
    }
    let token = data["accessToken"].as_str()?;
    let id = token.strip_prefix("m1.")?;
    (id.len() == 36 && uuid::Uuid::parse_str(id).ok()?.get_version_num() == 4).then_some(token)
}

#[derive(Default)]
struct Samples {
    ok_rtt_us: Vec<u64>,
    non_200: BTreeMap<u16, usize>,
    timeouts: usize,
    transport_errors: usize,
    invalid_200: usize,
    late: usize,
    late_ok: usize,
    login_budget_hit: bool,
}

impl Samples {
    // memory—v1: Merge thread-local counters and samples after draining the cell.
    fn merge(&mut self, worker: Self) {
        self.ok_rtt_us.extend(worker.ok_rtt_us);
        for (status, count) in worker.non_200 {
            *self.non_200.entry(status).or_default() += count;
        }
        self.timeouts += worker.timeouts;
        self.transport_errors += worker.transport_errors;
        self.invalid_200 += worker.invalid_200;
        self.late += worker.late;
        self.late_ok += worker.late_ok;
        self.login_budget_hit |= worker.login_budget_hit;
    }

    // memory—v1: Emit one JSON record per active request class, with a shared denominator.
    fn report(&self, cell: Cell, class: &str, workers: usize, drain: Duration) {
        let q = PhaseQuantile::summarize(&self.ok_rtt_us);
        let non_200_count: usize = self.non_200.values().sum();
        let ok = self.ok_rtt_us.len() - self.invalid_200;
        eprintln!(
            "login_curve {}",
            json!({
                "round": cell.round, "mode": cell.mode(), "class": class, "workers": workers,
                "readers": cell.readers, "logins": cell.logins, "window_us": WINDOW.as_micros() as u64,
                "drain_us": drain.as_micros() as u64, "request_timeout_ms": REQUEST_TIMEOUT.as_millis() as u64,
                "attempts": self.ok_rtt_us.len() + non_200_count + self.timeouts + self.transport_errors,
                "http_200": q.count, "ok": ok, "invalid_200": self.invalid_200,
                "non_200_count": non_200_count, "non_200_by_status": self.non_200,
                "timeouts": self.timeouts, "transport_errors": self.transport_errors,
                "late": self.late, "late_ok": self.late_ok,
                "ok_per_sec": ok as f64 / WINDOW.as_secs_f64(),
                "in_window_ok_per_sec": (ok - self.late_ok) as f64 / WINDOW.as_secs_f64(),
                "p50_us": (q.count > 0).then_some(q.p50_us),
                "p95_us": (q.count > 0).then_some(q.p95_us),
                "p99_us": (q.count > 0).then_some(q.p99_us),
                "login_budget_hit": self.login_budget_hit,
            })
        );
    }
}

// memory—v1: Admit independently until the common deadline and finish every admitted exchange.
async fn sample(class: Class, request: RequestBuilder, deadline: Instant) -> Samples {
    let mut samples = Samples::default();
    let is_login = matches!(class, Class::Login);
    let mut attempts = 0;
    loop {
        let began = Instant::now();
        if began >= deadline {
            break;
        }
        if is_login && attempts == LOGIN_ATTEMPTS_PER_WORKER {
            samples.login_budget_hit = true;
            break;
        }
        attempts += 1;
        let outcome = exchange(request.try_clone().expect("replayable fixture request")).await;
        let ended = Instant::now();
        let late = ended >= deadline;
        samples.late += usize::from(late);
        match outcome {
            Ok((StatusCode::OK, body)) => {
                samples.ok_rtt_us.push((ended - began).as_micros() as u64);
                if is_login
                    && serde_json::from_slice::<Value>(body.as_ref())
                        .ok()
                        .and_then(|body| response_token(&body).map(|_| ()))
                        .is_none()
                {
                    samples.invalid_200 += 1;
                } else {
                    samples.late_ok += usize::from(late);
                }
            }
            Ok((status, _)) => *samples.non_200.entry(status.as_u16()).or_default() += 1,
            Err(error) if error.is_timeout() => samples.timeouts += 1,
            Err(_) => samples.transport_errors += 1,
        }
    }
    samples
}

/// memory—v1: Warm independent client groups and release them into one timed cell.
pub(super) async fn measure(addr: SocketAddr, cell: Cell) -> Result<()> {
    ensure!(
        addr.ip().is_loopback(),
        "login curve requires loopback HTTP"
    );
    let endpoints = std::sync::Arc::new(Endpoints {
        login: format!("http://{addr}{LOGIN}"),
        registry: format!("http://{addr}{REGISTRY}"),
        registry_len: registry_declarations().len(),
    });
    // Issue the same one ALLOW session even for login-only cells to keep the
    // pre-cell setup comparable. Only the reader workers use this session.
    let setup_client = client()?;
    let token: std::sync::Arc<str> = endpoints
        .warm_login(
            &setup_client,
            endpoints.login_request(&setup_client, CARD_ALLOW),
        )
        .await?
        .into();
    drop(setup_client);

    let workers = cell.readers + cell.logins;
    let (ready_tx, mut ready_rx) = mpsc::channel(workers);
    let (start_tx, start_rx) = watch::channel(None::<Instant>);
    let mut jobs = JoinSet::new();
    for index in 0..workers {
        let class = if index < cell.readers {
            Class::Read
        } else {
            Class::Login
        };
        let endpoints = endpoints.clone();
        let token = token.clone();
        let ready_tx = ready_tx.clone();
        let mut start_rx = start_rx.clone();
        jobs.spawn(async move {
            let warm = async {
                let client = client()?;
                match class {
                    Class::Read => {
                        let request = endpoints.read_request(&client, &token);
                        endpoints
                            .warm_read(request.try_clone().expect("replayable fixture request"))
                            .await?;
                        Ok::<_, anyhow::Error>(request)
                    }
                    Class::Login => {
                        let request = endpoints.login_request(&client, CARD_BOB);
                        endpoints
                            .warm_login(
                                &client,
                                request.try_clone().expect("replayable fixture request"),
                            )
                            .await?;
                        Ok(request)
                    }
                }
            }
            .await;
            let request = match warm {
                Ok(request) => request,
                Err(error) => {
                    let _ = ready_tx.send(Err(error)).await;
                    return None;
                }
            };
            ready_tx.send(Ok(())).await.ok()?;
            drop(ready_tx);
            let deadline = (*start_rx.wait_for(Option::is_some).await.ok()?)?;
            Some((class, sample(class, request, deadline).await))
        });
    }
    drop(ready_tx);
    drop(start_rx);
    let ready = timeout(WARMUP_TIMEOUT, async {
        for _ in 0..workers {
            ready_rx
                .recv()
                .await
                .context("curve worker exited during warm-up")??;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("login curve warm-up exceeded its budget")
    .and_then(|result| result);
    if let Err(error) = ready {
        jobs.shutdown().await;
        return Err(error);
    }

    let deadline = Instant::now() + WINDOW;
    start_tx
        .send(Some(deadline))
        .context("release warmed curve workers")?;
    let mut read = Samples::default();
    let mut login = Samples::default();
    while let Some(result) = jobs.join_next().await {
        let (class, samples) = result
            .context("join login curve worker")?
            .context("curve worker did not measure")?;
        match class {
            Class::Read => read.merge(samples),
            Class::Login => login.merge(samples),
        }
    }
    let drain = Instant::now().saturating_duration_since(deadline);
    if cell.readers > 0 {
        read.report(cell, "read", cell.readers, drain);
    }
    if cell.logins > 0 {
        login.report(cell, "login", cell.logins, drain);
    }
    ensure!(
        !login.login_budget_hit,
        "login attempt guard reached before the cell deadline"
    );
    ensure!(
        login.invalid_200 == 0,
        "measured login returned an invalid 200 bearer"
    );
    Ok(())
}
