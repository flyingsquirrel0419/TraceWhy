//! TCP listener discovery from procfs.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;
use tracewhy_core::{InvestigationError, Listener};

/// Listening TCP sockets on `port`, with owning processes where visible.
pub fn listeners(port: u16, deadline: Instant) -> Result<Vec<Listener>, InvestigationError> {
    let mut found: Vec<(IpAddr, u64)> = Vec::new();
    let mut any_table = false;
    for (file, v6) in [("/proc/net/tcp", false), ("/proc/net/tcp6", true)] {
        if let Ok(text) = std::fs::read_to_string(file) {
            any_table = true;
            found.extend(parse_listen_table(&text, v6, port));
        }
    }
    if !any_table {
        return Err(InvestigationError::Unavailable(
            "/proc/net/tcp is not readable".into(),
        ));
    }
    let inodes: HashSet<u64> = found.iter().map(|(_, i)| *i).filter(|i| *i != 0).collect();
    let owners = if inodes.is_empty() {
        HashMap::new()
    } else {
        socket_owners(&inodes, deadline)
    };
    let mut out: Vec<Listener> = found
        .into_iter()
        .map(|(address, inode)| {
            let pid = owners.get(&inode).copied();
            Listener {
                address,
                pid,
                executable: pid
                    .and_then(|p| std::fs::read_link(format!("/proc/{p}/exe")).ok())
                    .map(|p| p.to_string_lossy().into_owned()),
                cmdline: pid.and_then(cmdline),
            }
        })
        .collect();
    out.sort_by(|a, b| a.address.cmp(&b.address).then(a.pid.cmp(&b.pid)));
    out.dedup();
    Ok(out)
}

fn cmdline(pid: u32) -> Option<String> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let parts: Vec<String> = raw
        .split(|b| *b == 0)
        .filter(|p| !p.is_empty())
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .collect();
    let s = parts.join(" ");
    (!s.is_empty()).then(|| s.chars().take(200).collect())
}

/// Parse a /proc/net/tcp{,6} table, returning (address, inode) of LISTEN sockets on `port`.
pub fn parse_listen_table(text: &str, v6: bool, port: u16) -> Vec<(IpAddr, u64)> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 || cols[3] != "0A" {
            continue;
        }
        let Some((addr_hex, port_hex)) = cols[1].split_once(':') else {
            continue;
        };
        if u16::from_str_radix(port_hex, 16).ok() != Some(port) {
            continue;
        }
        let Some(addr) = parse_addr(addr_hex, v6) else {
            continue;
        };
        let inode = cols[9].parse().unwrap_or(0);
        out.push((addr, inode));
    }
    out
}

fn parse_addr(hex: &str, v6: bool) -> Option<IpAddr> {
    if !v6 {
        let n = u32::from_str_radix(hex, 16).ok()?;
        // procfs prints each 32-bit word in host byte order.
        return Some(IpAddr::V4(Ipv4Addr::from(n.to_ne_bytes())));
    }
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for w in 0..4 {
        let word = u32::from_str_radix(hex.get(w * 8..w * 8 + 8)?, 16).ok()?;
        bytes[w * 4..w * 4 + 4].copy_from_slice(&word.to_ne_bytes());
    }
    let a = Ipv6Addr::from(bytes);
    Some(match a.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(a),
    })
}

/// Map socket inodes to the pid holding them by scanning /proc/*/fd.
fn socket_owners(inodes: &HashSet<u64>, deadline: Instant) -> HashMap<u64, u32> {
    let mut out = HashMap::new();
    let Ok(procs) = std::fs::read_dir("/proc") else {
        return out;
    };
    for entry in procs.flatten() {
        if Instant::now() >= deadline || out.len() == inodes.len() {
            break;
        }
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(target) = std::fs::read_link(fd.path()) else {
                continue;
            };
            let t = target.to_string_lossy();
            if let Some(inode) = t
                .strip_prefix("socket:[")
                .and_then(|r| r.strip_suffix(']'))
                .and_then(|n| n.parse::<u64>().ok())
            {
                if inodes.contains(&inode) {
                    out.entry(inode).or_insert(pid);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_net_tcp() {
        let text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 4242 1 0 100 0 0 10 0\n   1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 77 1\n   2: 0100007F:1538 0100007F:9C40 01 00000000:00000000 00:00000000 00000000   999        0 4243 1\n";
        let r = parse_listen_table(text, false, 5432);
        assert_eq!(r, vec![("127.0.0.1".parse().unwrap(), 4242)]);
        let r = parse_listen_table(text, false, 8080);
        assert_eq!(r, vec![("0.0.0.0".parse().unwrap(), 77)]);
    }

    #[test]
    fn parses_ipv6() {
        let text = "hdr\n   0: 00000000000000000000000001000000:1538 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  0 0 9 1\n   1: 00000000000000000000000000000000:1538 00000000000000000000000000000000:0000 0A 0 0 0 0 0 10 1\n";
        let r = parse_listen_table(text, true, 5432);
        assert_eq!(r[0].0, "::1".parse::<IpAddr>().unwrap());
        assert_eq!(r[1].0, "::".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn finds_a_real_listener() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let found = listeners(port, Instant::now() + std::time::Duration::from_secs(5)).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].pid, Some(std::process::id()));
        drop(l);
        let found = listeners(port, Instant::now() + std::time::Duration::from_secs(5)).unwrap();
        assert!(found.is_empty());
    }
}
