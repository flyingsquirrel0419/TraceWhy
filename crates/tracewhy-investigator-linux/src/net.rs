//! DNS resolution, local addresses and routes.

use crate::sys;
use std::net::{IpAddr, ToSocketAddrs};
use std::time::Duration;
use tracewhy_core::{FactKind, InvestigationError};

/// Resolve `name` now (bounded by `budget`) and read the resolver config.
pub fn resolve(name: &str, budget: Duration) -> Result<Vec<FactKind>, InvestigationError> {
    let mut out = Vec::new();
    let host = name.to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    // getaddrinfo cannot be cancelled; a detached thread bounds our wait.
    std::thread::spawn(move || {
        let r = (host.as_str(), 0)
            .to_socket_addrs()
            .map(|it| it.map(|a| a.ip()).collect::<Vec<IpAddr>>());
        let _ = tx.send(r);
    });
    let wait = budget.min(Duration::from_secs(5));
    match rx.recv_timeout(wait) {
        Ok(Ok(mut addrs)) => {
            addrs.sort();
            addrs.dedup();
            out.push(FactKind::DnsResolution {
                hostname: name.to_string(),
                addresses: addrs,
                error: None,
            });
        }
        Ok(Err(e)) => out.push(FactKind::DnsResolution {
            hostname: name.to_string(),
            addresses: Vec::new(),
            error: Some(e.to_string()),
        }),
        Err(_) => return Err(InvestigationError::TimedOut),
    }
    if let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") {
        out.push(parse_resolv_conf(&text));
    }
    Ok(out)
}

pub fn parse_resolv_conf(text: &str) -> FactKind {
    let mut nameservers = Vec::new();
    let mut search = Vec::new();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        match it.next() {
            Some("nameserver") => nameservers.extend(it.next().map(String::from)),
            Some("search") | Some("domain") => search.extend(it.map(String::from)),
            _ => {}
        }
    }
    FactKind::ResolverConfig {
        nameservers,
        search,
    }
}

pub fn network() -> Vec<FactKind> {
    let ipv4 = std::fs::read_to_string("/proc/net/route")
        .map(|t| {
            t.lines()
                .skip(1)
                .any(|l| l.split_whitespace().nth(1) == Some("00000000"))
        })
        .unwrap_or(false);
    let ipv6 = std::fs::read_to_string("/proc/net/ipv6_route")
        .map(|t| {
            t.lines().any(|l| {
                let c: Vec<&str> = l.split_whitespace().collect();
                c.len() > 9
                    && c[0] == "00000000000000000000000000000000"
                    && c[1] == "00"
                    && c[9] != "lo"
            })
        })
        .unwrap_or(false);
    vec![
        FactKind::LocalAddresses {
            addresses: sys::local_addresses(),
        },
        FactKind::DefaultRoute { ipv4, ipv6 },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolv_conf() {
        let f = parse_resolv_conf(
            "# c\nnameserver 127.0.0.53\noptions edns0\nsearch a.example b.example\n",
        );
        assert_eq!(
            f,
            FactKind::ResolverConfig {
                nameservers: vec!["127.0.0.53".into()],
                search: vec!["a.example".into(), "b.example".into()]
            }
        );
    }

    #[test]
    fn localhost_resolves() {
        let f = resolve("localhost", Duration::from_secs(5)).unwrap();
        assert!(
            matches!(&f[0], FactKind::DnsResolution { addresses, .. } if !addresses.is_empty())
        );
    }

    #[test]
    fn has_loopback() {
        let f = network();
        assert!(
            matches!(&f[0], FactKind::LocalAddresses { addresses } if addresses.iter().any(|a| a.is_loopback()))
        );
    }
}
