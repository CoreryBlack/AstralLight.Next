//! Endpoint policy: SSRF binding, allowlist, redirection off, TLS.
//!
//! The guard is applied twice:
//! 1. at configuration resolution (`check_url`) — before any socket exists;
//! 2. at DNS resolution ([`GuardedResolver`]/`validate_resolved_ip`) — so a
//!    hostname cannot resolve to a protected address (DNS rebinding, metadata
//!    services, internal networks).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::Url;

use crate::delivery::state::DeliveryError;

/// Endpoint admission policy for outbound HTTP delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointGuard {
    /// Allow loopback targets. `false` for production; `true` only for
    /// isolated loopback test fixtures.
    allow_loopback: bool,
    /// Exact-host allowlist (case-insensitive). Empty means any host that
    /// passes IP policy.
    allowed_hosts: Vec<String>,
}

impl EndpointGuard {
    /// Production guard: no loopback, no private ranges; optional allowlist.
    pub fn public(allowed_hosts: Vec<String>) -> Self {
        Self {
            allow_loopback: false,
            allowed_hosts: lowercase(allowed_hosts),
        }
    }

    /// Loopback fixture guard (tests only): loopback allowed, private ranges
    /// still limited to loopback.
    pub fn loopback_fixture(allowed_hosts: Vec<String>) -> Self {
        Self {
            allow_loopback: true,
            allowed_hosts: lowercase(allowed_hosts),
        }
    }

    pub fn allowed_hosts(&self) -> &[String] {
        &self.allowed_hosts
    }

    pub fn allows_loopback(&self) -> bool {
        self.allow_loopback
    }

    /// Validate an outbound URL. Returns the normalized absolute URL string.
    pub fn check_url(&self, raw: &str) -> Result<Url, DeliveryError> {
        if raw.len() > 2048 {
            return Err(DeliveryError::Bounds("endpoint url"));
        }
        let url = Url::parse(raw)
            .map_err(|_| DeliveryError::InvalidConfig("endpoint url is not absolute"))?;
        if !matches!(url.scheme(), "https" | "http") {
            return Err(DeliveryError::EndpointBlocked(
                "only https (or http to loopback fixtures) is allowed",
            ));
        }
        if url.scheme() == "http" && !self.allow_loopback {
            return Err(DeliveryError::EndpointBlocked(
                "plain http requires the loopback fixture profile",
            ));
        }
        // Credentials in the URL would leak into logs.
        if !url.username().is_empty() || url.password().is_some() {
            return Err(DeliveryError::EndpointBlocked(
                "userinfo in endpoint url is forbidden",
            ));
        }
        let host = url
            .host_str()
            .filter(|h| !h.is_empty())
            .ok_or(DeliveryError::InvalidConfig("endpoint url has no host"))?;
        if !self.allowed_hosts.is_empty()
            && !self
                .allowed_hosts
                .iter()
                .any(|allowed| allowed == &host.to_ascii_lowercase())
        {
            return Err(DeliveryError::EndpointBlocked(
                "host is not on the endpoint allowlist",
            ));
        }
        // host_str keeps IPv6 brackets; strip them before the literal check.
        let bare_host = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = bare_host.parse::<IpAddr>() {
            self.validate_ip(ip)?;
        }
        // Port: https must be explicit-or-443; http loopback any. No fragment.
        if url.fragment().is_some() {
            return Err(DeliveryError::EndpointBlocked(
                "endpoint url fragment is not allowed",
            ));
        }
        Ok(url)
    }

    /// Validate one resolved address against SSRF policy.
    pub fn validate_ip(&self, ip: IpAddr) -> Result<(), DeliveryError> {
        let blocked = match ip {
            IpAddr::V4(v4) => !self.v4_allowed(v4),
            IpAddr::V6(v6) => !self.v6_allowed(v6),
        };
        if blocked {
            return Err(DeliveryError::EndpointBlocked(
                "resolved address is in a protected range",
            ));
        }
        Ok(())
    }

    fn v4_allowed(&self, ip: Ipv4Addr) -> bool {
        let o = ip.octets();
        if ip.is_loopback() {
            return self.allow_loopback;
        }
        // Unspecified, private (RFC1918), link-local (incl. cloud metadata),
        // broadcast, multicast, benchmark/documentation ranges: protected.
        if o[0] == 0
            || o[0] == 10
            || o[0] == 127
            || (o[0] == 100 && (64..=127).contains(&o[1])) // CGNAT 100.64/10
            || (o[0] == 169 && o[1] == 254)
            || (o[0] == 172 && (16..=31).contains(&o[1]))
            || (o[0] == 192 && o[1] == 168)
            || (o[0] == 192 && o[1] == 0 && o[2] == 2)
            || (o[0] == 198 && o[1] == 18)
            || (o[0] == 198 && o[1] == 51 && o[2] == 100)
            || (o[0] == 203 && o[1] == 0 && o[2] == 113)
            || o == [255, 255, 255, 255]
            || o[0] >= 224
        {
            return false;
        }
        true
    }

    fn v6_allowed(&self, ip: Ipv6Addr) -> bool {
        if ip.is_loopback() {
            return self.allow_loopback;
        }
        let segments = ip.segments();
        // Unspecified ::, IPv4-mapped ::ffff:0:0/96, ULA fc00::/7,
        // link-local fe80::/10, multicast, documentation 2001:db8::/32.
        if segments == [0, 0, 0, 0, 0, 0, 0, 0]
            || segments[0] == 0
                && segments[1] == 0
                && segments[2] == 0
                && segments[3] == 0
                && segments[4] == 0
                && (segments[5] == 0 || segments[5] == 0xffff)
            || (segments[0] & 0xfe00) == 0xfc00
            || (segments[0] & 0xffc0) == 0xfe80
            || segments[0] & 0xff00 == 0xff00
            || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        {
            return false;
        }
        true
    }
}

fn lowercase(items: Vec<String>) -> Vec<String> {
    items
        .into_iter()
        .map(|item| item.trim().to_ascii_lowercase())
        .filter(|item| !item.is_empty())
        .collect()
}

/// DNS resolver for reqwest that pins resolution through endpoint policy:
/// every resolved address is validated; requests to protected ranges fail
/// before any connection is attempted.
pub struct GuardedResolver {
    guard: EndpointGuard,
}

impl GuardedResolver {
    pub fn new(guard: EndpointGuard) -> Self {
        Self { guard }
    }
}

impl Resolve for GuardedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let guard = self.guard.clone();
        let host = name.as_str().to_owned();
        Box::pin(async move {
            // Re-check allowlist at resolution time (host may differ from the
            // URL the caller validated).
            if !guard.allowed_hosts.is_empty()
                && !guard
                    .allowed_hosts
                    .iter()
                    .any(|allowed| allowed == &host.to_ascii_lowercase())
            {
                return Err(boxed(DeliveryError::EndpointBlocked(
                    "host is not on the endpoint allowlist",
                )));
            }
            let resolved = tokio::net::lookup_host((host.as_str(), 0u16))
                .await
                .map_err(|error| {
                    boxed(DeliveryError::Transport(format!("dns failure: {error}")))
                })?;
            let mut allowed: Vec<std::net::SocketAddr> = Vec::new();
            for socket in resolved {
                if guard.validate_ip(socket.ip()).is_ok() {
                    allowed.push(socket);
                }
            }
            if allowed.is_empty() {
                return Err(boxed(DeliveryError::EndpointBlocked(
                    "all resolved addresses are in protected ranges",
                )));
            }
            let addrs: Addrs = Box::new(allowed.into_iter());
            Ok(addrs)
        })
    }
}

fn boxed(error: DeliveryError) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(error)
}

/// Convenience: build a guarded, hardened reqwest client (redirection off,
/// bounded timeouts). Shared per process by the delivery owner.
pub fn guarded_client(guard: EndpointGuard) -> Result<reqwest::Client, DeliveryError> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .read_timeout(std::time::Duration::from_secs(10))
        .connect_timeout(std::time::Duration::from_secs(5))
        .dns_resolver(Arc::new(GuardedResolver::new(guard)))
        .build()
        .map_err(|error| DeliveryError::Transport(format!("http client build failed: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_guard_blocks_loopback_and_private_urls() {
        let guard = EndpointGuard::public(vec![]);
        assert!(guard.check_url("http://127.0.0.1/hook").is_err());
        assert!(guard.check_url("http://10.0.0.1/hook").is_err());
        assert!(guard
            .check_url("http://169.254.169.254/latest/meta-data")
            .is_err());
        assert!(guard.check_url("https://192.168.1.4/hook").is_err());
        assert!(guard.check_url("ftp://example.com").is_err());
        assert!(guard
            .check_url("https://user:pass@example.com/hook")
            .is_err());
        assert!(guard.check_url("https://example.com/hook#frag").is_err());
    }

    #[test]
    fn public_guard_allows_public_https() {
        let guard = EndpointGuard::public(vec![]);
        let url = guard.check_url("https://hooks.example.com/hook").unwrap();
        assert_eq!(url.host_str(), Some("hooks.example.com"));
    }

    #[test]
    fn allowlist_is_exact_and_case_insensitive() {
        let guard = EndpointGuard::public(vec!["Sms.Provider.Example.com".into()]);
        assert!(guard
            .check_url("https://sms.provider.example.com/send")
            .is_ok());
        assert!(guard
            .check_url("https://sms.provider.example.com.evil.test/send")
            .is_err());
        assert!(guard.check_url("https://evil.test/…").is_err());
    }

    #[test]
    fn loopback_fixture_guard_admits_only_loopback_http() {
        let guard = EndpointGuard::loopback_fixture(vec![]);
        assert!(guard.check_url("http://127.0.0.1:0/x").is_ok());
        assert!(guard.check_url("http://10.1.2.3/x").is_err());
        assert!(guard.check_url("https://[::1]/x").is_ok());
        assert!(guard.check_url("https://[fc00::1]/x").is_err());
    }

    #[test]
    fn resolved_addresses_are_filtered_by_policy() {
        let public = EndpointGuard::public(vec![]);
        assert!(public.validate_ip("8.8.8.8".parse().unwrap()).is_ok());
        assert!(public.validate_ip("127.0.0.1".parse().unwrap()).is_err());
        assert!(public
            .validate_ip("169.254.169.254".parse().unwrap())
            .is_err());
        assert!(public.validate_ip("100.64.0.1".parse().unwrap()).is_err());
        assert!(public.validate_ip("0.0.0.0".parse().unwrap()).is_err());
        assert!(public.validate_ip("224.0.0.1".parse().unwrap()).is_err());
        assert!(public.validate_ip("::1".parse().unwrap()).is_err());
        assert!(public.validate_ip("fe80::1".parse().unwrap()).is_err());
        assert!(public.validate_ip("2001:db8::1".parse().unwrap()).is_err());
        let fixture = EndpointGuard::loopback_fixture(vec![]);
        assert!(fixture.validate_ip("127.0.0.1".parse().unwrap()).is_ok());
        assert!(fixture.validate_ip("::1".parse().unwrap()).is_ok());
        assert!(fixture.validate_ip("10.0.0.9".parse().unwrap()).is_err());
    }
}
