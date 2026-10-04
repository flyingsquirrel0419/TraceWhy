//! Command-line parsing.
//!
//! `why [OPTIONS] <command> [args...]` must pass the traced command through
//! untouched, so parsing stops at the first non-option argument (or `--`).
//! Subcommands are recognized only in that first position.

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GlobalOpts {
    pub verbose: bool,
    pub json: bool,
    pub color: ColorChoice,
    pub investigate: bool,
    pub output: Option<String>,
    pub unsafe_no_redact: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ColorChoice {
    #[default]
    Auto,
    Always,
    Never,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cmd {
    Run { argv: Vec<String> },
    Record { argv: Vec<String> },
    Show { file: String },
    Explain { file: String },
    Diff { good: String, bad: String },
    Doctor,
    Version,
    Help,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    pub opts: GlobalOpts,
    pub cmd: Cmd,
}

pub const USAGE: &str = "\
TraceWhy — understand why a command failed.

Usage:
  why [OPTIONS] <command> [args...]     Run a command and explain its failure
  why record [-o FILE] <command> ...    Run and save a .whytrace file
  why show FILE                         Show the conclusion stored in a trace
  why explain [--investigate] FILE      Re-run the analysis on a stored trace
  why diff GOOD BAD                     Compare a working and a broken trace
  why doctor                            Check that tracing works here
  why version                           Print the version

Options:
  -v, --verbose          Show observations, hypotheses, investigations, facts
      --json             Machine-readable JSON on stdout
      --color WHEN       auto (default), always, never; NO_COLOR is honored
      --no-color         Same as --color never
      --no-investigate   Do not probe the system after the run (trace only)
  -o, --output FILE      Also save a .whytrace file (record: output path)
      --unsafe-no-redact Export secrets unredacted (never the default)
  -h, --help             Show this help
  -V, --version          Show the version
      --                 End of TraceWhy options

Exit status:
  The traced command's own exit status (128+N if killed by signal N).
  124  unsupported environment (strace missing or tracing blocked)
  125  TraceWhy internal error
  2    invalid TraceWhy usage (subcommands)
";

pub fn parse(args: &[String]) -> Result<Parsed, String> {
    let mut opts = GlobalOpts {
        investigate: true,
        ..GlobalOpts::default()
    };
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--" => {
                i += 1;
                break;
            }
            "-v" | "--verbose" => opts.verbose = true,
            "--json" => opts.json = true,
            "--no-color" => opts.color = ColorChoice::Never,
            "--no-investigate" => opts.investigate = false,
            "--unsafe-no-redact" => opts.unsafe_no_redact = true,
            "-h" | "--help" => {
                return Ok(Parsed {
                    opts,
                    cmd: Cmd::Help,
                })
            }
            "-V" | "--version" => {
                return Ok(Parsed {
                    opts,
                    cmd: Cmd::Version,
                })
            }
            "--color" => {
                i += 1;
                opts.color = color(args.get(i).map(|s| s.as_str()))?;
            }
            "-o" | "--output" => {
                i += 1;
                opts.output = Some(args.get(i).cloned().ok_or("-o requires a file name")?);
            }
            _ if a.starts_with("--color=") => opts.color = color(Some(&a["--color=".len()..]))?,
            _ if a.starts_with("--output=") => {
                opts.output = Some(a["--output=".len()..].to_string())
            }
            _ if a.starts_with('-') && a.len() > 1 => {
                return Err(format!(
                "unknown option {a:?} (use `why -- {a} ...` to run a command starting with '-')"
            ))
            }
            _ => break,
        }
        i += 1;
    }
    let rest = &args[i..];
    let explicit_command = i > 0 && args.get(i - 1).map(|s| s == "--").unwrap_or(false);
    let Some(first) = rest.first() else {
        return Ok(Parsed {
            opts,
            cmd: Cmd::Help,
        });
    };
    if explicit_command {
        return Ok(Parsed {
            opts,
            cmd: Cmd::Run {
                argv: rest.to_vec(),
            },
        });
    }
    let sub_args = &rest[1..];
    let cmd = match first.as_str() {
        "record" => {
            let (opts2, argv) = sub_opts(sub_args, &mut opts)?;
            opts = opts2;
            if argv.is_empty() {
                return Err("record: missing command".into());
            }
            Cmd::Record { argv }
        }
        "show" => Cmd::Show {
            file: one_file(sub_args, &mut opts, "show")?,
        },
        "explain" => {
            // Re-analysis uses recorded facts unless --investigate is given.
            opts.investigate = false;
            Cmd::Explain {
                file: one_file(sub_args, &mut opts, "explain")?,
            }
        }
        "diff" => {
            let (opts2, files) = sub_opts(sub_args, &mut opts)?;
            opts = opts2;
            if files.len() != 2 {
                return Err("diff: expected two files: why diff GOOD.whytrace BAD.whytrace".into());
            }
            Cmd::Diff {
                good: files[0].clone(),
                bad: files[1].clone(),
            }
        }
        "doctor" => {
            let (opts2, _) = sub_opts(sub_args, &mut opts)?;
            opts = opts2;
            Cmd::Doctor
        }
        "version" => Cmd::Version,
        "help" => Cmd::Help,
        _ => Cmd::Run {
            argv: rest.to_vec(),
        },
    };
    Ok(Parsed { opts, cmd })
}

fn color(v: Option<&str>) -> Result<ColorChoice, String> {
    match v {
        Some("auto") => Ok(ColorChoice::Auto),
        Some("always") => Ok(ColorChoice::Always),
        Some("never") => Ok(ColorChoice::Never),
        other => Err(format!(
            "--color expects auto, always or never (got {other:?})"
        )),
    }
}

/// Options allowed after a subcommand, then positional arguments. For
/// `record`, everything from the first non-option on is the command.
fn sub_opts(args: &[String], opts: &mut GlobalOpts) -> Result<(GlobalOpts, Vec<String>), String> {
    let mut o = opts.clone();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--" => {
                i += 1;
                break;
            }
            "-v" | "--verbose" => o.verbose = true,
            "--json" => o.json = true,
            "--no-color" => o.color = ColorChoice::Never,
            "--no-investigate" => o.investigate = false,
            "--investigate" => o.investigate = true,
            "--unsafe-no-redact" => o.unsafe_no_redact = true,
            "--color" => {
                i += 1;
                o.color = color(args.get(i).map(|s| s.as_str()))?;
            }
            "-o" | "--output" => {
                i += 1;
                o.output = Some(args.get(i).cloned().ok_or("-o requires a file name")?);
            }
            a if a.starts_with("--color=") => o.color = color(Some(&a["--color=".len()..]))?,
            a if a.starts_with("--output=") => o.output = Some(a["--output=".len()..].to_string()),
            a if a.starts_with('-') && a.len() > 1 => return Err(format!("unknown option {a:?}")),
            _ => break,
        }
        i += 1;
    }
    Ok((o, args[i..].to_vec()))
}

fn one_file(args: &[String], opts: &mut GlobalOpts, name: &str) -> Result<String, String> {
    let (o, files) = sub_opts(args, opts)?;
    if o.output.is_some() {
        return Err(format!(
            "{name}: -o/--output is not supported (use `why record -o FILE <command>`)"
        ));
    }
    *opts = o;
    match files.as_slice() {
        [f] => Ok(f.clone()),
        _ => Err(format!("{name}: expected exactly one .whytrace file")),
    }
}

#[cfg(test)]
mod tests;
