//! Compose file parsing: `docker compose config --format json` output, and a
//! small fallback reader for the subset of YAML needed when Docker is absent.

use serde_json::Value;
use tracewhy_core::{ComposeService, PortMapping};

pub fn from_config_json(text: &str) -> Option<(Option<String>, Vec<ComposeService>)> {
    let v: Value = serde_json::from_str(text).ok()?;
    let project = v.get("name").and_then(|n| n.as_str()).map(String::from);
    let services = v.get("services")?.as_object()?;
    let mut out = Vec::new();
    for (name, s) in services {
        let ports = s
            .get("ports")
            .and_then(|p| p.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|p| {
                        let target = p.get("target")?.as_u64()? as u16;
                        let published = match p.get("published") {
                            Some(Value::String(s)) => {
                                s.split('-').next().and_then(|x| x.parse().ok())
                            }
                            Some(Value::Number(n)) => n.as_u64().map(|x| x as u16),
                            _ => None,
                        };
                        Some(PortMapping {
                            host_ip: p.get("host_ip").and_then(|x| x.as_str()).map(String::from),
                            host_port: published,
                            container_port: target,
                            protocol: p
                                .get("protocol")
                                .and_then(|x| x.as_str())
                                .unwrap_or("tcp")
                                .to_string(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let expose = s
            .get("expose")
            .and_then(|e| e.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| match x {
                        Value::String(s) => s.split('/').next().and_then(|p| p.parse().ok()),
                        Value::Number(n) => n.as_u64().map(|x| x as u16),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        out.push(ComposeService {
            name: name.clone(),
            image: s.get("image").and_then(|i| i.as_str()).map(String::from),
            ports,
            expose,
            healthcheck: s.get("healthcheck").map(|h| !h.is_null()).unwrap_or(false),
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Some((project, out))
}

/// `docker compose ps --format json` prints either a JSON array or one object per line.
pub fn parse_ps_json(text: &str) -> Vec<Value> {
    let t = text.trim();
    if t.starts_with('[') {
        return serde_json::from_str::<Vec<Value>>(t).unwrap_or_default();
    }
    t.lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .collect()
}

/// Parse `docker ps` Ports column: `0.0.0.0:5432->5432/tcp, :::5432->5432/tcp`.
pub fn parse_ps_ports(s: &str) -> Vec<PortMapping> {
    let mut out: Vec<PortMapping> = Vec::new();
    for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let Some((host, cont)) = part.split_once("->") else {
            continue;
        };
        let (cport, proto) = cont.split_once('/').unwrap_or((cont, "tcp"));
        let Some((ip, hport)) = host.rsplit_once(':') else {
            continue;
        };
        let (Ok(h), Ok(c)) = (hport.parse::<u16>(), cport.parse::<u16>()) else {
            continue;
        };
        let m = PortMapping {
            host_ip: Some(ip.to_string()),
            host_port: Some(h),
            container_port: c,
            protocol: proto.to_string(),
        };
        if !out
            .iter()
            .any(|x| x.host_port == m.host_port && x.container_port == m.container_port)
        {
            out.push(m);
        }
    }
    out
}

/// Parse a short-syntax port spec: `5432`, `5432:5432`, `127.0.0.1:5432:5432/tcp`,
/// `[::1]:80:80`, `8000-8002:8000-8002`.
pub fn parse_port_spec(spec: &str) -> Vec<PortMapping> {
    let spec = spec.trim().trim_matches(|c| c == '"' || c == '\'');
    let (body, proto) = spec.split_once('/').unwrap_or((spec, "tcp"));
    let (ip, rest) = if let Some(r) = body.strip_prefix('[') {
        match r.split_once("]:") {
            Some((ip, rest)) => (Some(ip.to_string()), rest),
            None => return Vec::new(),
        }
    } else {
        let parts: Vec<&str> = body.split(':').collect();
        if parts.len() == 3 {
            (Some(parts[0].to_string()), &body[parts[0].len() + 1..])
        } else {
            (None, body)
        }
    };
    let (host, cont) = match rest.split_once(':') {
        Some((h, c)) => (Some(h), c),
        None => (None, rest),
    };
    let range = |s: &str| -> Option<(u16, u16)> {
        match s.split_once('-') {
            Some((a, b)) => Some((a.parse().ok()?, b.parse().ok()?)),
            None => {
                let v = s.parse().ok()?;
                Some((v, v))
            }
        }
    };
    let Some((c0, c1)) = range(cont) else {
        return Vec::new();
    };
    let host_r = match host {
        Some(h) if !h.is_empty() => range(h),
        _ => None,
    };
    let mut out = Vec::new();
    for (i, c) in (c0..=c1).take(256).enumerate() {
        let hp = host_r.map(|(h0, h1)| {
            if h0 == h1 {
                h0
            } else {
                h0.saturating_add(i as u16)
            }
        });
        out.push(PortMapping {
            host_ip: ip.clone(),
            host_port: hp,
            container_port: c,
            protocol: proto.to_string(),
        });
    }
    out
}

fn indent(l: &str) -> usize {
    l.len() - l.trim_start().len()
}

fn scalar(v: &str) -> String {
    let v = v.split(" #").next().unwrap_or(v).trim();
    v.trim_matches(|c| c == '"' || c == '\'').to_string()
}

/// Minimal YAML reader for compose files: services, image, ports, expose, healthcheck.
pub fn parse_compose_yaml(text: &str) -> Vec<ComposeService> {
    let lines: Vec<&str> = text
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .collect();
    let mut out: Vec<ComposeService> = Vec::new();
    let Some(start) = lines
        .iter()
        .position(|l| indent(l) == 0 && l.trim_end().starts_with("services:"))
    else {
        return out;
    };
    let mut svc_indent = None;
    let mut cur: Option<ComposeService> = None;
    let mut section: Option<(String, usize)> = None;
    let mut long_port: Option<(Option<u16>, Option<u16>)> = None;
    let flush_long = |cur: &mut Option<ComposeService>,
                      lp: &mut Option<(Option<u16>, Option<u16>)>| {
        if let (Some(c), Some((Some(t), p))) = (cur.as_mut(), lp.take()) {
            c.ports.push(PortMapping {
                host_ip: None,
                host_port: p,
                container_port: t,
                protocol: "tcp".into(),
            });
        }
    };
    for l in &lines[start + 1..] {
        let ind = indent(l);
        if ind == 0 {
            break;
        }
        let t = l.trim();
        let si = *svc_indent.get_or_insert(ind);
        if ind == si {
            flush_long(&mut cur, &mut long_port);
            if let Some(c) = cur.take() {
                out.push(c);
            }
            let name = t.trim_end_matches(':').trim().to_string();
            cur = Some(ComposeService {
                name: scalar(&name),
                image: None,
                ports: Vec::new(),
                expose: Vec::new(),
                healthcheck: false,
            });
            section = None;
            continue;
        }
        let Some(c) = cur.as_mut() else { continue };
        if let Some((name, sind)) = &section {
            if ind > *sind {
                if let Some(item) = t.strip_prefix("- ") {
                    if name == "ports" {
                        flush_long(&mut cur, &mut long_port);
                        let item = item.trim();
                        if let Some((k, v)) = item
                            .split_once(':')
                            .filter(|(k, _)| matches!(k.trim(), "target" | "published"))
                        {
                            long_port = Some((None, None));
                            set_long(&mut long_port, k.trim(), &scalar(v));
                        } else if let Some(cc) = cur.as_mut() {
                            cc.ports.extend(parse_port_spec(&scalar(item)));
                        }
                    } else if name == "expose" {
                        if let Some(p) = scalar(item).split('/').next().and_then(|p| p.parse().ok())
                        {
                            c.expose.push(p);
                        }
                    }
                } else if name == "ports" {
                    if let Some((k, v)) = t.split_once(':') {
                        set_long(&mut long_port, k.trim(), &scalar(v));
                    }
                }
                continue;
            }
            flush_long(&mut cur, &mut long_port);
            section = None;
        }
        let Some(c) = cur.as_mut() else { continue };
        if let Some((k, v)) = t.split_once(':') {
            let (k, v) = (k.trim(), v.trim());
            match k {
                "image" => c.image = Some(scalar(v)),
                "healthcheck" => c.healthcheck = true,
                "ports" | "expose" => {
                    if v.starts_with('[') {
                        for item in v.trim_matches(|x| x == '[' || x == ']').split(',') {
                            if k == "ports" {
                                c.ports.extend(parse_port_spec(&scalar(item)));
                            } else if let Ok(p) = scalar(item).parse() {
                                c.expose.push(p);
                            }
                        }
                    } else {
                        section = Some((k.to_string(), ind));
                    }
                }
                _ => {}
            }
        }
    }
    flush_long(&mut cur, &mut long_port);
    if let Some(c) = cur.take() {
        out.push(c);
    }
    out
}

fn set_long(lp: &mut Option<(Option<u16>, Option<u16>)>, k: &str, v: &str) {
    let e = lp.get_or_insert((None, None));
    match k {
        "target" => e.0 = v.parse().ok(),
        "published" => e.1 = v.split('-').next().and_then(|x| x.parse().ok()),
        _ => {}
    }
}

#[cfg(test)]
mod tests;
