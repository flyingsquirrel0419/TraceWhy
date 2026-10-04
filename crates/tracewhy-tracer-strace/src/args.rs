//! Helpers for decoding strace argument syntax.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracewhy_event::Endpoint;

/// Split an argument list at top-level commas.
pub fn split_args(args: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let bytes = args.as_bytes();
    let mut depth: i32 = 0;
    let mut in_str = false;
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if in_str {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == b'"' {
                in_str = false;
            }
        } else {
            match b {
                b'"' => in_str = true,
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => depth -= 1,
                b',' if depth == 0 => {
                    out.push(args[start..i].trim());
                    start = i + 1;
                }
                _ => {}
            }
        }
        i += 1;
    }
    let last = args.get(start..).unwrap_or("").trim();
    if !last.is_empty() || !out.is_empty() {
        out.push(last);
    }
    out
}

/// Decode a C-escaped string body (without surrounding quotes) into bytes.
pub fn unescape(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'\\' || i + 1 >= b.len() {
            out.push(b[i]);
            i += 1;
            continue;
        }
        let c = b[i + 1];
        i += 2;
        match c {
            b'n' => out.push(b'\n'),
            b't' => out.push(b'\t'),
            b'r' => out.push(b'\r'),
            b'v' => out.push(0x0b),
            b'f' => out.push(0x0c),
            b'a' => out.push(0x07),
            b'b' => out.push(0x08),
            b'e' => out.push(0x1b),
            b'x' => {
                let mut v: u32 = 0;
                let mut n = 0;
                while n < 2 && i < b.len() && b[i].is_ascii_hexdigit() {
                    v = v * 16 + (b[i] as char).to_digit(16).unwrap_or(0);
                    i += 1;
                    n += 1;
                }
                out.push(v as u8);
            }
            b'0'..=b'7' => {
                let mut v: u32 = u32::from(c - b'0');
                let mut n = 1;
                while n < 3 && i < b.len() && (b'0'..=b'7').contains(&b[i]) {
                    v = v * 8 + u32::from(b[i] - b'0');
                    i += 1;
                    n += 1;
                }
                out.push((v & 0xff) as u8);
            }
            other => out.push(other),
        }
    }
    out
}

/// Parse a quoted string argument. Returns the decoded bytes and whether it was truncated.
pub fn parse_string_bytes(arg: &str) -> Option<(Vec<u8>, bool)> {
    let arg = arg.trim();
    let arg = arg.strip_prefix('@').unwrap_or(arg);
    let body = arg.strip_prefix('"')?;
    let end = closing_quote(body)?;
    let truncated = body[end + 1..].starts_with("...");
    Some((unescape(&body[..end]), truncated))
}

pub fn parse_string(arg: &str) -> Option<String> {
    parse_string_bytes(arg).map(|(b, _)| String::from_utf8_lossy(&b).into_owned())
}

fn closing_quote(body: &str) -> Option<usize> {
    let b = body.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'"' => return Some(i),
            _ => i += 1,
        }
    }
    None
}

/// All quoted strings appearing anywhere in `s`, decoded, in order.
pub fn all_strings(s: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut rest = s;
    while let Some(start) = rest.find('"') {
        let body = &rest[start + 1..];
        match closing_quote(body) {
            Some(end) => {
                out.push(unescape(&body[..end]));
                rest = &body[end + 1..];
            }
            None => break,
        }
    }
    out
}

/// Parse a `["a", "b"]` string array (argv).
pub fn parse_string_array(arg: &str) -> Vec<String> {
    let arg = arg.trim();
    let Some(inner) = arg
        .strip_prefix('[')
        .and_then(|a| a.rsplit_once(']'))
        .map(|(a, _)| a)
    else {
        return Vec::new();
    };
    split_args(inner)
        .into_iter()
        .filter_map(parse_string)
        .collect()
}

/// A file-descriptor argument with its `-yy` annotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FdArg {
    /// `None` means `AT_FDCWD`.
    pub fd: Option<i64>,
    pub annotation: Option<String>,
}

pub fn parse_fd(arg: &str) -> Option<FdArg> {
    let arg = arg.trim();
    let (head, annotation) = match arg.find('<') {
        Some(i) if arg.ends_with('>') => (&arg[..i], Some(arg[i + 1..arg.len() - 1].to_string())),
        _ => (arg, None),
    };
    if head == "AT_FDCWD" {
        return Some(FdArg {
            fd: None,
            annotation,
        });
    }
    head.parse().ok().map(|fd| FdArg {
        fd: Some(fd),
        annotation,
    })
}

/// Parse a socket address structure.
pub fn parse_sockaddr(arg: &str) -> Option<Endpoint> {
    let arg = arg.trim();
    if !arg.starts_with('{') {
        return None;
    }
    if arg.contains("sa_family=AF_UNIX") {
        let i = arg.find("sun_path=")?;
        let path = parse_string(&arg[i + "sun_path=".len()..])?;
        let abstract_ns = arg[i + "sun_path=".len()..].starts_with('@');
        let path = if abstract_ns {
            format!("@{path}")
        } else {
            path
        };
        return Some(Endpoint::Unix { path });
    }
    let port = {
        let i = arg.find("htons(")?;
        let r = &arg[i + 6..];
        r[..r.find(')')?].trim().parse::<u16>().ok()?
    };
    if arg.contains("sa_family=AF_INET6") {
        let i = arg.find("inet_pton(AF_INET6,")?;
        let r = &arg[i + "inet_pton(AF_INET6,".len()..];
        let addr: Ipv6Addr = parse_string(r)?.parse().ok()?;
        let address = match addr.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(addr),
        };
        return Some(Endpoint::Inet { address, port });
    }
    if arg.contains("sa_family=AF_INET") {
        let i = arg.find("inet_addr(")?;
        let addr: Ipv4Addr = parse_string(&arg[i + "inet_addr(".len()..])?.parse().ok()?;
        return Some(Endpoint::Inet {
            address: IpAddr::V4(addr),
            port,
        });
    }
    None
}

/// Parse the endpoint pair of a `-yy` socket annotation such as
/// `TCP:[127.0.0.1:4321->127.0.0.1:5432]`. Returns `(protocol, local, peer)`.
pub fn parse_socket_annotation(ann: &str) -> Option<(String, Option<String>, Option<String>)> {
    let colon = ann.find(":[")?;
    let proto = ann[..colon].to_string();
    let inner = ann[colon + 2..].strip_suffix(']')?;
    if let Some((l, r)) = inner.split_once("->") {
        Some((proto, Some(l.to_string()), Some(r.to_string())))
    } else if inner.bytes().all(|b| b.is_ascii_digit()) {
        Some((proto, None, None))
    } else {
        Some((proto, Some(inner.to_string()), None))
    }
}

/// Port number at the end of an `addr:port` / `[v6]:port` string.
pub fn port_of(addr: &str) -> Option<u16> {
    addr.rsplit_once(':').and_then(|(_, p)| p.parse().ok())
}

#[cfg(test)]
mod tests;
