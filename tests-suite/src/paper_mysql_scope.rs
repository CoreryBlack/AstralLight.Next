// Shared test-only admission for the approved, pre-provisioned MySQL paper fixture.

pub const URL_ENV: &str = "ASTRAL_PAPER_MYSQL_URL";
pub const APPROVAL_ENV: &str = "ASTRAL_PAPER_MYSQL_APPROVED_RUN";
pub const RUN_ENV: &str = "ASTRAL_PAPER_MYSQL_RUN_ID";
pub const PORT: u16 = 3308;

pub fn schema_name(run: &str) -> Result<String, &'static str> {
    if run.is_empty()
        || run.len() > 32
        || !run.as_bytes()[0].is_ascii_lowercase()
        || !run
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        return Err("MySQL run id must start with a lowercase letter and contain at most 32 lowercase letters, digits or underscores");
    }
    Ok(format!("astral_rehearsal_paper_{run}"))
}

pub fn validate(url: &url::Url, run: &str, approved: &str) -> Result<String, &'static str> {
    let schema = schema_name(run)?;
    if run != approved {
        return Err("operator approval must match the paper run id");
    }
    if url.scheme() != "mysql"
        || url
            .host_str()
            .and_then(|host| host.parse::<std::net::Ipv4Addr>().ok())
            != Some(std::net::Ipv4Addr::LOCALHOST)
        || url.port() != Some(PORT)
        || url.path().strip_prefix('/') != Some(schema.as_str())
        || url.username().is_empty()
        || !url
            .username()
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        || url.username().eq_ignore_ascii_case("root")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("MySQL fixture URL must use the dedicated non-root loopback account on port 3308 and name exactly the run-scoped schema; options are not allowed");
    }
    Ok(schema)
}
