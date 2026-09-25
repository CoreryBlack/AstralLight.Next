//! AstralLight 真实系统上限压测客户端。
//!
//! 独立 crate（自带 `[workspace]`，不在 AstralLight-Rust members 内）。
//! 替代 python requests + GIL 客户端（F3 实测瓶颈：50 线程实际并发仅 5-10，
//! P90 215ms 来自客户端排队而非服务端）。tokio 多线程 + 连接池复用 +
//! HMAC v3 网关签名，closed-loop / open-loop 两种压测模型。
//!
//! 用法示例：
//! ```text
//! loadgen --url http://127.0.0.1:9005 \
//!   --path /main/api/v1/rule-sets/9071/entries \
//!   --concurrency 128 --duration 20 --warmup 50 \
//!   --hmac-secret "$SECRET" --output json
//! ```

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const USAGE: &str = "\
loadgen — AstralLight HMAC v3 压测客户端（GIL-free）

用法:
  loadgen [选项]

选项:
      --url <URL>             目标 base url（默认 http://127.0.0.1:9005）
      --path <PATH>           请求路径（默认 /main/api/v1/rule-sets/9071/entries）
      --method <M>            GET|POST|PUT（默认 GET）
      --body <BODY>           POST/PUT 请求体
  -c, --concurrency <N>       closed-loop 并发任务数（默认 1）
  -d, --duration <SEC>        测量时长秒（默认 20）
  -n, --count <N>             总请求数（>0 时优先于 --duration）
      --warmup <N>            预热请求数（不计入统计，默认 0）
      --rate <RPS>            open-loop 固定速率（0 = closed-loop，默认 0）
      --threads <N>           tokio worker 线程数（0 = 全部核，默认 0）
      --timeout-ms <MS>       单请求超时（默认 10000）
      --hmac-secret <S>       HMAC 密钥（缺省读环境变量 LOADGEN_HMAC_SECRET）
      --prefix <S>            签名前缀（默认 astral-gateway-v3）
      --user-id <ID>          平台用户 id（默认 9031）
      --icard <ID>            identity card id（默认 9041）
      --card <ID>             user card id（默认 9061）
      --domain <ID>           domain id（默认 9011）
      --tenant <ID>           tenant id（默认 9001）
      --output <MODE>         text|json（默认 text）
  -h, --help                  帮助
";

#[derive(Debug, Clone)]
struct Ids {
    user: String,
    icard: String,
    card: String,
    domain: String,
    tenant: String,
}

#[derive(Debug)]
struct Args {
    url: String,
    path: String,
    method: String,
    body: Option<String>,
    concurrency: u64,
    duration: f64,
    count: u64,
    warmup: u64,
    rate: f64,
    threads: usize,
    timeout_ms: u64,
    secret: String,
    prefix: String,
    ids: Ids,
    json: bool,
}

fn parse_args() -> Result<Args, String> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.iter().any(|a| a == "-h" || a == "--help") {
        print!("{USAGE}");
        std::process::exit(0);
    }
    let mut url = String::from("http://127.0.0.1:9005");
    let mut path = String::from("/main/api/v1/rule-sets/9071/entries");
    let mut method = String::from("GET");
    let mut body: Option<String> = None;
    let mut concurrency: u64 = 1;
    let mut duration: f64 = 20.0;
    let mut count: u64 = 0;
    let mut warmup: u64 = 0;
    let mut rate: f64 = 0.0;
    let mut threads: usize = 0;
    let mut timeout_ms: u64 = 10_000;
    let mut secret = String::new();
    let mut prefix = String::from("astral-gateway-v3");
    let mut user = String::from("9031");
    let mut icard = String::from("9041");
    let mut card = String::from("9061");
    let mut domain = String::from("9011");
    let mut tenant = String::from("9001");
    let mut json = false;

    let mut idx = 0;
    while idx < argv.len() {
        let flag = argv[idx].as_str();
        let mut next = || -> Result<String, String> {
            idx += 1;
            argv.get(idx)
                .cloned()
                .ok_or_else(|| format!("缺少 {flag} 的值"))
        };
        match flag {
            "--url" => url = next()?,
            "--path" => path = next()?,
            "--method" => method = next()?.to_uppercase(),
            "--body" => body = Some(next()?),
            "-c" | "--concurrency" => concurrency = next()?.parse().map_err(|e| format!("--concurrency: {e}"))?,
            "-d" | "--duration" => duration = next()?.parse().map_err(|e| format!("--duration: {e}"))?,
            "-n" | "--count" => count = next()?.parse().map_err(|e| format!("--count: {e}"))?,
            "--warmup" => warmup = next()?.parse().map_err(|e| format!("--warmup: {e}"))?,
            "--rate" => rate = next()?.parse().map_err(|e| format!("--rate: {e}"))?,
            "--threads" => threads = next()?.parse().map_err(|e| format!("--threads: {e}"))?,
            "--timeout-ms" => timeout_ms = next()?.parse().map_err(|e| format!("--timeout-ms: {e}"))?,
            "--hmac-secret" => secret = next()?,
            "--prefix" => prefix = next()?,
            "--user-id" => user = next()?,
            "--icard" => icard = next()?,
            "--card" => card = next()?,
            "--domain" => domain = next()?,
            "--tenant" => tenant = next()?,
            "--output" => json = next()?.eq_ignore_ascii_case("json"),
            other => return Err(format!("未知参数 {other}（--help 查看用法）")),
        }
        idx += 1;
    }

    if secret.is_empty() {
        secret = std::env::var("LOADGEN_HMAC_SECRET").unwrap_or_default();
    }
    if secret.is_empty() {
        return Err("缺少 HMAC 密钥：--hmac-secret 或环境变量 LOADGEN_HMAC_SECRET".into());
    }
    if !matches!(method.as_str(), "GET" | "POST" | "PUT" | "DELETE") {
        return Err(format!("不支持的 method: {method}"));
    }
    Ok(Args {
        url: url.trim_end_matches('/').to_owned(),
        path,
        method,
        body,
        concurrency: concurrency.max(1),
        duration,
        count,
        warmup,
        rate,
        threads,
        timeout_ms,
        secret,
        prefix,
        ids: Ids { user, icard, card, domain, tenant },
        json,
    })
}

fn now_millis() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_millis()
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// 与 F3 load_test.py 完全一致的签名 payload 布局。
fn sign(secret: &str, prefix: &str, method: &str, path: &str, ids: &Ids, ts: &str) -> String {
    let payload = [
        prefix,
        method,
        path,
        ids.user.as_str(),
        "PLATFORM_USER",
        "",
        ids.icard.as_str(),
        ids.card.as_str(),
        ids.domain.as_str(),
        ids.tenant.as_str(),
        "",
        "",
        "",
        "",
        ts,
    ]
    .join("\n");
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(payload.as_bytes());
    hex(&mac.finalize().into_bytes())
}

/// xorshift64* 伪随机，用于 x-request-id（uuid v4 形态，仅要求唯一性）。
struct Png(u64);
impl Png {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn uuid_v4_like(&mut self) -> String {
        let hi = self.next();
        let lo = self.next();
        format!(
            "{:08x}-{:04x}-4{:03x}-8{:03x}-{:012x}",
            (hi >> 32) as u32,
            ((hi >> 16) & 0xffff) as u16,
            (hi & 0xfff) as u16,
            ((lo >> 48) & 0xfff) as u16,
            lo & 0xffff_ffff_ffff
        )
    }
}

struct Stats {
    ok: AtomicU64,
    err: AtomicU64,
    codes: [AtomicU64; 600],
    lat_us: Mutex<Vec<u64>>,
}

impl Stats {
    fn new() -> Self {
        Self {
            ok: AtomicU64::new(0),
            err: AtomicU64::new(0),
            codes: std::array::from_fn(|_| AtomicU64::new(0)),
            lat_us: Mutex::new(Vec::new()),
        }
    }

    fn record_ok(&self, code: u16, us: u64) {
        self.lat_us.lock().unwrap().push(us);
        self.codes[(code as usize).min(599)].fetch_add(1, Ordering::Relaxed);
        self.ok.fetch_add(1, Ordering::Relaxed);
    }

    fn record_err(&self, us: u64) {
        self.lat_us.lock().unwrap().push(us);
        self.err.fetch_add(1, Ordering::Relaxed);
    }
}

struct Ctx {
    client: reqwest::Client,
    base: String,
    path: String,
    method: String,
    body: Option<String>,
    secret: String,
    prefix: String,
    ids: Ids,
    png: Mutex<Png>,
}

async fn one_request(ctx: &Ctx, stats: &Stats) {
    let t0 = Instant::now();
    let path_no_q = ctx.path.split('?').next().unwrap_or(ctx.path.as_str());
    let ts = now_millis().to_string();
    let sig = sign(&ctx.secret, &ctx.prefix, &ctx.method, path_no_q, &ctx.ids, &ts);
    let req_id = {
        let mut p = ctx.png.lock().unwrap();
        p.uuid_v4_like()
    };
    let url = format!("{}{}", ctx.base, ctx.path);
    let mut req = match ctx.method.as_str() {
        "POST" => ctx.client.post(&url),
        "PUT" => ctx.client.put(&url),
        "DELETE" => ctx.client.delete(&url),
        _ => ctx.client.get(&url),
    };
    req = req
        .header("content-type", "application/json")
        .header("x-request-id", req_id)
        .header("x-user-id", &ctx.ids.user)
        .header("x-principal-kind", "PLATFORM_USER")
        .header("x-identity-card-id", &ctx.ids.icard)
        .header("x-user-card-id", &ctx.ids.card)
        .header("x-user-card-domain-id", &ctx.ids.domain)
        .header("x-user-card-tenant-id", &ctx.ids.tenant)
        .header("x-gateway-auth", "verified")
        .header("x-gateway-ts", &ts)
        .header("x-gateway-signature", sig);
    if let Some(b) = &ctx.body {
        req = req.body(b.clone());
    }
    match req.send().await {
        Ok(resp) => {
            let code = resp.status().as_u16();
            match resp.bytes().await {
                Ok(_) => stats.record_ok(code, t0.elapsed().as_micros() as u64),
                Err(_) => stats.record_err(t0.elapsed().as_micros() as u64),
            }
        }
        Err(_) => stats.record_err(t0.elapsed().as_micros() as u64),
    }
}

/// closed-loop：N 个任务各自循环发请求直到 deadline。
async fn run_closed_loop(ctx: Arc<Ctx>, stats: Arc<Stats>, concurrency: usize, deadline: Instant) {
    let mut handles = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let ctx = ctx.clone();
        let stats = stats.clone();
        handles.push(tokio::spawn(async move {
            while Instant::now() < deadline {
                one_request(&ctx, &stats).await;
            }
        }));
    }
    for h in handles {
        let _ = h.await;
    }
}

/// 计数模式：确定性分片——每个 worker 固定发 `total/concurrency` 个请求
/// （前 `total%concurrency` 个 worker 多发一个），无共享计数器竞态。
async fn run_count(ctx: Arc<Ctx>, stats: Arc<Stats>, concurrency: usize, total: u64) {
    let concurrency = concurrency.max(1) as u64;
    let base = total / concurrency;
    let rem = total % concurrency;
    let mut handles = Vec::with_capacity(concurrency as usize);
    for w in 0..concurrency {
        let n = base + u64::from(w < rem);
        if n == 0 {
            continue;
        }
        let ctx = ctx.clone();
        let stats = stats.clone();
        handles.push(tokio::spawn(async move {
            for _ in 0..n {
                one_request(&ctx, &stats).await;
            }
        }));
    }
    for h in handles {
        let _ = h.await;
    }
}

/// open-loop：固定速率 pacing，每 tick 派发一个请求，in-flight 不反压闭环。
async fn run_open_loop(
    ctx: Arc<Ctx>,
    stats: Arc<Stats>,
    rate: f64,
    deadline: Instant,
) {
    let mut tick = tokio::time::interval(Duration::from_secs_f64(1.0 / rate));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut handles = Vec::new();
    while Instant::now() < deadline {
        tick.tick().await;
        let ctx = ctx.clone();
        let stats = stats.clone();
        handles.push(tokio::spawn(async move { one_request(&ctx, &stats).await }));
    }
    for h in handles {
        let _ = h.await;
    }
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((p / 100.0) * (sorted.len() - 1) as f64).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn report(args: &Args, wall: Duration, stats: &Stats) {
    let mut lat = stats.lat_us.lock().unwrap().clone();
    lat.sort_unstable();
    let ok = stats.ok.load(Ordering::Relaxed);
    let err = stats.err.load(Ordering::Relaxed);
    let qps = ok as f64 / wall.as_secs_f64().max(1e-9);
    let mean = if lat.is_empty() { 0 } else { lat.iter().sum::<u64>() / lat.len() as u64 };
    let p50 = percentile(&lat, 50.0);
    let p90 = percentile(&lat, 90.0);
    let p99 = percentile(&lat, 99.0);
    let p999 = percentile(&lat, 99.9);
    let max = lat.last().copied().unwrap_or(0);
    let mut codes = String::new();
    for (code, cnt) in stats.codes.iter().enumerate() {
        let c = cnt.load(Ordering::Relaxed);
        if c > 0 {
            if !codes.is_empty() {
                codes.push(',');
            }
            codes.push_str(&format!("\"{code}\":{c}"));
        }
    }

    if args.json {
        println!(
            "{{\"concurrency\":{},\"rate\":{},\"duration_s\":{:.3},\"ok\":{},\"err\":{},\"qps\":{:.1},\
             \"mean_us\":{},\"p50_us\":{},\"p90_us\":{},\"p99_us\":{},\"p999_us\":{},\"max_us\":{},\"codes\":{{{}}}}}",
            args.concurrency, args.rate, wall.as_secs_f64(), ok, err, qps,
            mean, p50, p90, p99, p999, max, codes
        );
    } else {
        println!(
            "并发={} rate={} 墙钟={:.2}s | ok={} err={} QPS={:.1}\n延迟(µs): mean={} p50={} p90={} p99={} p999={} max={}\n状态码: {}",
            args.concurrency, args.rate, wall.as_secs_f64(), ok, err, qps,
            mean, p50, p90, p99, p999, max,
            if codes.is_empty() { "-" } else { &codes }
        );
    }
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("loadgen: {e}\n{USAGE}");
            std::process::exit(2);
        }
    };
    let threads = if args.threads == 0 {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4)
    } else {
        args.threads
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(run(args));
}

async fn run(args: Args) {
    let client = reqwest::Client::builder()
        .tcp_nodelay(true)
        .timeout(Duration::from_millis(args.timeout_ms))
        .pool_idle_timeout(Duration::from_secs(75))
        .pool_max_idle_per_host(args.concurrency as usize + 8)
        .build()
        .expect("http client");
    let ctx = Arc::new(Ctx {
        client,
        base: args.url.clone(),
        path: args.path.clone(),
        method: args.method.clone(),
        body: args.body.clone(),
        secret: args.secret.clone(),
        prefix: args.prefix.clone(),
        ids: args.ids.clone(),
        png: Mutex::new(Png(
            (now_millis() as u64) ^ 0x9E3779B97F4A7C15 ^ (args.concurrency << 1 | 1),
        )),
    });

    if args.warmup > 0 {
        let t0 = Instant::now();
        let stats = Arc::new(Stats::new());
        run_count(ctx.clone(), stats, (args.concurrency as usize).min(64), args.warmup).await;
        eprintln!("预热 {} 请求完成，用时 {:.2}s", args.warmup, t0.elapsed().as_secs_f64());
    }

    let stats = Arc::new(Stats::new());
    let t0 = Instant::now();
    if args.count > 0 {
        run_count(
            ctx.clone(),
            stats.clone(),
            args.concurrency as usize,
            args.count,
        )
        .await;
    } else if args.rate > 0.0 {
        run_open_loop(
            ctx.clone(),
            stats.clone(),
            args.rate,
            t0 + Duration::from_secs_f64(args.duration),
        )
        .await;
    } else {
        run_closed_loop(
            ctx.clone(),
            stats.clone(),
            args.concurrency as usize,
            t0 + Duration::from_secs_f64(args.duration),
        )
        .await;
    }
    let wall = t0.elapsed();
    report(&args, wall, &stats);
}
