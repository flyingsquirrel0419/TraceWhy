//! `why` — TraceWhy's command-line interface.

mod args;
mod doctor;
mod run;
mod sys;

use args::{Cmd, ColorChoice, GlobalOpts};
use std::io::Write;
use std::path::Path;
use tracewhy_core::Limits;
use tracewhy_format::WhyTrace;
use tracewhy_redact::Redactor;
use tracewhy_report::ReportOptions;

const EXIT_USAGE: i32 = 2;
const EXIT_UNSUPPORTED: i32 = 124;
const EXIT_INTERNAL: i32 = 125;

fn main() {
    let argv: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let code = match args::parse(&argv) {
        Ok(p) => dispatch(p.opts, p.cmd),
        Err(e) => {
            eprintln!("why: {e}\n\nRun `why --help` for usage.");
            EXIT_USAGE
        }
    };
    let _ = std::io::stdout().flush();
    std::process::exit(code);
}

fn use_color(choice: ColorChoice, fd: i32) -> bool {
    match choice {
        ColorChoice::Always => true,
        ColorChoice::Never => false,
        ColorChoice::Auto => {
            std::env::var_os("NO_COLOR")
                .map(|v| v.is_empty())
                .unwrap_or(true)
                && std::env::var("TERM").map(|t| t != "dumb").unwrap_or(true)
                && sys::isatty(fd)
        }
    }
}

fn redactor(opts: &GlobalOpts) -> Option<Redactor> {
    (!opts.unsafe_no_redact).then(Redactor::new)
}

/// Print the report for a trace: JSON to stdout, or text to the given stream.
fn print_trace(t: &WhyTrace, opts: &GlobalOpts, to_stderr: bool) {
    let r = redactor(opts);
    if opts.json {
        let mut v = tracewhy_report::json::report(t);
        if let Some(r) = &r {
            r.redact_value(&mut v);
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&v).unwrap_or_else(|_| "{}".into())
        );
        return;
    }
    let fd = if to_stderr { 2 } else { 1 };
    let text = tracewhy_report::render(
        t,
        &ReportOptions {
            verbose: opts.verbose,
            color: use_color(opts.color, fd),
        },
    );
    let text = match &r {
        Some(r) => r.redact(&text).into_owned(),
        None => text,
    };
    if to_stderr {
        eprint!("{text}");
    } else {
        print!("{text}");
    }
}

fn save(t: &WhyTrace, path: &str, opts: &GlobalOpts) -> bool {
    let r = redactor(opts);
    if opts.unsafe_no_redact {
        eprintln!("why: warning: writing {path} WITHOUT redaction; it may contain secrets.");
    }
    match t.write(Path::new(path), r.as_ref()) {
        Ok(()) => {
            eprintln!("why: trace saved to {path}");
            true
        }
        Err(e) => {
            eprintln!("why: {e}");
            false
        }
    }
}

fn load(path: &str) -> Result<WhyTrace, i32> {
    WhyTrace::read(Path::new(path)).map_err(|e| {
        eprintln!("why: {e}");
        EXIT_INTERNAL
    })
}

fn default_record_name() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("tracewhy-{secs}.whytrace")
}

fn dispatch(opts: GlobalOpts, cmd: Cmd) -> i32 {
    match cmd {
        Cmd::Help => {
            print!("{}", args::USAGE);
            0
        }
        Cmd::Version => {
            println!("TraceWhy {}", run::VERSION);
            0
        }
        Cmd::Doctor => doctor::run(opts.json, use_color(opts.color, 1)),
        Cmd::Run { argv } => {
            match run::trace_command(&argv, opts.investigate, Limits::default(), opts.json) {
                Ok(t) => {
                    // Report on stderr would interleave with the program's output
                    // anyway; stdout keeps `why cmd > report.txt` useful.
                    print_trace(&t.trace, &opts, false);
                    if let Some(o) = &opts.output {
                        if !save(&t.trace, o, &opts) {
                            return EXIT_INTERNAL;
                        }
                    }
                    t.exit_code
                }
                Err(e) => run_error(e),
            }
        }
        Cmd::Record { argv } => {
            match run::trace_command(&argv, opts.investigate, Limits::default(), opts.json) {
                Ok(t) => {
                    let path = opts.output.clone().unwrap_or_else(default_record_name);
                    if !opts.json {
                        print_trace(&t.trace, &opts, true);
                    }
                    if !save(&t.trace, &path, &opts) {
                        return EXIT_INTERNAL;
                    }
                    if opts.json {
                        println!(
                            "{}",
                            serde_json::json!({"saved": path, "exit_code": t.exit_code})
                        );
                    }
                    t.exit_code
                }
                Err(e) => run_error(e),
            }
        }
        Cmd::Show { file } => match load(&file) {
            Ok(t) => {
                print_trace(&t, &opts, false);
                0
            }
            Err(c) => c,
        },
        Cmd::Explain { file } => match load(&file) {
            Ok(t) => {
                // Without --investigate the analysis uses only recorded facts.
                let t2 = run::reanalyze(&t, opts.investigate);
                print_trace(&t2, &opts, false);
                0
            }
            Err(c) => c,
        },
        Cmd::Diff { good, bad } => {
            let (g, b) = match (load(&good), load(&bad)) {
                (Ok(g), Ok(b)) => (g, b),
                (Err(c), _) | (_, Err(c)) => return c,
            };
            let d = tracewhy_diff::diff(&g, &b);
            let r = redactor(&opts);
            if opts.json {
                let mut v = serde_json::to_value(&d).unwrap_or_default();
                if let Some(r) = &r {
                    r.redact_value(&mut v);
                }
                println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
            } else {
                let text = tracewhy_report::render_diff(&d, use_color(opts.color, 1), opts.verbose);
                print!(
                    "{}",
                    r.as_ref()
                        .map(|r| r.redact(&text).into_owned())
                        .unwrap_or(text)
                );
            }
            0
        }
    }
}

fn run_error(e: run::RunError) -> i32 {
    match e {
        run::RunError::Unsupported(m) => {
            eprintln!("why: unsupported environment: {m}");
            EXIT_UNSUPPORTED
        }
        run::RunError::Internal(m) => {
            eprintln!("why: internal error: {m}");
            EXIT_INTERNAL
        }
    }
}
