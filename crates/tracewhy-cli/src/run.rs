//! Tracing a command and turning the result into a `.whytrace`.

use crate::sys;
use std::path::{Path, PathBuf};
use tracewhy_core::{EnvSnapshot, Fact, Limits, ObservationKind};
use tracewhy_engine::{AnalysisInput, Engine, PreflightObservation};
use tracewhy_event::{
    BackendError, CommandSpec, Errno, Event, ExitStatus, ProcessTree, TraceBackend, TraceStats,
};
use tracewhy_format::{EnvFingerprint, RunInfo, WhyTrace, FORMAT_NAME, FORMAT_VERSION};
use tracewhy_tracer_strace::StraceBackend;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn engine(limits: Limits) -> Engine {
    let mut investigators = tracewhy_investigator_linux::investigators();
    investigators.extend(tracewhy_investigator_docker::investigators());
    let adapters: Vec<Box<dyn tracewhy_core::RuntimeAdapter>> = vec![
        Box::new(tracewhy_adapter_node::NodeAdapter),
        Box::new(tracewhy_adapter_python::PythonAdapter),
    ];
    let mut e = Engine::new(investigators, adapters);
    e.limits = limits;
    e
}

pub enum RunError {
    Unsupported(String),
    Internal(String),
}

/// Why the program cannot even be started, determined before tracing.
fn preflight(program: &str, env: &EnvSnapshot, cwd: &Path) -> Option<(ObservationKind, i32)> {
    let check = |p: &Path| -> Option<(Errno, i32)> {
        match std::fs::metadata(p) {
            Err(_) => Some((Errno::new("ENOENT"), 127)),
            Ok(m) if m.is_dir() => Some((Errno::new("EACCES"), 126)),
            Ok(_) if !sys::can_execute(p) => Some((Errno::new("EACCES"), 126)),
            Ok(_) => None,
        }
    };
    if program.contains('/') {
        let p = if program.starts_with('/') {
            PathBuf::from(program)
        } else {
            cwd.join(program)
        };
        let (error, code) = check(&p)?;
        let shown = if program.starts_with('/') {
            program.to_string()
        } else {
            p.to_string_lossy().into_owned()
        };
        return Some((
            ObservationKind::ExecFailed {
                executable: shown,
                error,
                attempts: vec![program.to_string()],
            },
            code,
        ));
    }
    let dirs = env.path_dirs();
    let mut denied = None;
    for d in &dirs {
        let base = if d.starts_with('/') {
            PathBuf::from(d)
        } else {
            cwd.join(d)
        };
        let p = base.join(program);
        match check(&p) {
            None => return None,
            Some((e, _)) if e.is("EACCES") && p.is_file() => denied = denied.or(Some(p)),
            _ => {}
        }
    }
    match denied {
        Some(p) => Some((
            ObservationKind::ExecFailed {
                executable: p.to_string_lossy().into_owned(),
                error: Errno::new("EACCES"),
                attempts: vec![program.to_string()],
            },
            126,
        )),
        None => Some((
            ObservationKind::ExecFailed {
                executable: program.to_string(),
                error: Errno::new("ENOENT"),
                attempts: dirs.iter().map(|d| format!("{d}/{program}")).collect(),
            },
            127,
        )),
    }
}

pub struct Traced {
    pub trace: WhyTrace,
    /// Exit status to return from `why`.
    pub exit_code: i32,
}

pub fn trace_command(
    argv: &[String],
    investigate: bool,
    limits: Limits,
    stdout_to_stderr: bool,
) -> Result<Traced, RunError> {
    let cwd = std::env::current_dir()
        .map_err(|e| RunError::Internal(format!("cannot determine the working directory: {e}")))?;
    let env = EnvSnapshot::from_current();
    let Some(program) = argv.first() else {
        return Err(RunError::Internal("no command given".into()));
    };
    let spec = CommandSpec {
        program: program.clone(),
        args: argv[1..].to_vec(),
        cwd: cwd.clone(),
        stdout_to_stderr,
    };
    let engine = engine(limits.clone());

    if let Some((obs, code)) = preflight(program, &env, &cwd) {
        let tree = ProcessTree::default();
        let exit = ExitStatus::Exited { code };
        let analysis = engine.analyze(AnalysisInput {
            command: argv.to_vec(),
            events: &[],
            tree: &tree,
            exit: Some(exit.clone()),
            cwd: cwd.clone(),
            env: &env,
            preflight: vec![PreflightObservation {
                kind: obs,
                facts: Vec::new(),
            }],
            prior_facts: Vec::new(),
            investigate,
        });
        let trace = assemble(
            argv,
            &cwd,
            &env,
            Vec::new(),
            tree,
            TraceStats::default(),
            Vec::new(),
            Some(exit),
            now(),
            0,
            None,
            analysis,
        );
        return Ok(Traced {
            trace,
            exit_code: code,
        });
    }

    let backend = StraceBackend::detect().map_err(|e| match e {
        BackendError::Unsupported(m) => RunError::Unsupported(m),
        other => RunError::Internal(other.to_string()),
    })?;
    let mut backend = backend;
    backend.limits.max_events = limits.max_semantic_events;
    backend.limits.max_output_bytes_per_process = limits.max_output_text_bytes;
    backend.max_raw_bytes = limits.max_raw_trace_bytes;

    let guard = sys::ignore_interrupts();
    let out = backend.run(&spec);
    drop(guard);
    let out = out.map_err(|e| match e {
        BackendError::Unsupported(m) => RunError::Unsupported(m),
        other => RunError::Internal(other.to_string()),
    })?;
    let tree = ProcessTree::build(&out.events);
    let mut exit = out.exit.clone();
    // If the command itself could not be executed, strace's child exits 1;
    // report the shell-standard status instead (127 not found, 126 not runnable).
    if let Some(root) = tree.root {
        let root_execs: Vec<&Event> = out.events.iter().filter(|e| e.pid == root).collect();
        let ran = root_execs
            .iter()
            .any(|e| matches!(e.kind, tracewhy_event::EventKind::ProcessExec { .. }));
        if !ran {
            if let Some(err) = root_execs.iter().rev().find_map(|e| match &e.kind {
                tracewhy_event::EventKind::ExecFailed { error, .. } => Some(error.clone()),
                _ => None,
            }) {
                let code = if err.is("ENOENT") { 127 } else { 126 };
                exit = Some(ExitStatus::Exited { code });
            }
        }
    }
    let exit_code = exit.as_ref().map(|e| e.shell_code()).unwrap_or(125);
    let analysis = engine.analyze(AnalysisInput {
        command: argv.to_vec(),
        events: &out.events,
        tree: &tree,
        exit: exit.clone(),
        cwd: cwd.clone(),
        env: &env,
        preflight: Vec::new(),
        prior_facts: Vec::new(),
        investigate,
    });
    let trace = assemble(
        argv,
        &cwd,
        &env,
        out.events,
        tree,
        out.stats,
        out.diagnostics,
        exit,
        out.started_at,
        out.duration_ms,
        Some(out.backend),
        analysis,
    );
    Ok(Traced { trace, exit_code })
}

/// Re-run the analysis over a stored trace (`why explain`).
pub fn reanalyze(t: &WhyTrace, investigate: bool) -> WhyTrace {
    let engine = engine(Limits::default());
    // The recorded environment (allowlisted values only, e.g. PATH, VIRTUAL_ENV).
    let env = EnvSnapshot {
        vars: t
            .environment
            .variables
            .iter()
            .filter_map(|(k, v)| Some((k.clone(), v.clone()?)))
            .collect(),
    };
    let prior: Vec<Fact> = if investigate {
        Vec::new()
    } else {
        t.facts.clone()
    };
    let mut tree = t.process_tree.clone();
    if tree.processes.is_empty() && !t.events.is_empty() {
        tree = ProcessTree::build(&t.events);
    }
    let preflight = if t.events.is_empty() {
        t.observations
            .iter()
            .filter(|o| o.events.is_empty())
            .map(|o| PreflightObservation {
                kind: o.kind.clone(),
                facts: Vec::new(),
            })
            .collect()
    } else {
        Vec::new()
    };
    let analysis = engine.analyze(AnalysisInput {
        command: t.run.command.clone(),
        events: &t.events,
        tree: &tree,
        exit: t.run.exit.clone(),
        cwd: PathBuf::from(&t.run.cwd),
        env: &env,
        preflight,
        prior_facts: prior,
        investigate,
    });
    let mut out = t.clone();
    out.process_tree = tree;
    out.observations = analysis.observations;
    out.facts = analysis.facts;
    out.hypotheses = analysis.hypotheses;
    if investigate {
        out.investigations = analysis.investigations;
    }
    out.graph = analysis.graph;
    out.conclusion = analysis.conclusion;
    out
}

fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[allow(clippy::too_many_arguments)]
fn assemble(
    argv: &[String],
    cwd: &Path,
    env: &EnvSnapshot,
    events: Vec<Event>,
    tree: ProcessTree,
    stats: TraceStats,
    mut diagnostics: Vec<tracewhy_event::Diagnostic>,
    exit: Option<ExitStatus>,
    started_at: f64,
    duration_ms: u64,
    backend: Option<tracewhy_event::BackendInfo>,
    analysis: tracewhy_engine::Analysis,
) -> WhyTrace {
    for w in &analysis.warnings {
        diagnostics.push(tracewhy_event::Diagnostic {
            line: None,
            message: w.clone(),
        });
    }
    let mut environment = EnvFingerprint::capture(&env.vars);
    environment.uid = Some(sys::euid());
    WhyTrace {
        format: FORMAT_NAME.into(),
        format_version: FORMAT_VERSION,
        tracewhy_version: VERSION.into(),
        run: RunInfo {
            command: argv.to_vec(),
            cwd: cwd.to_string_lossy().into_owned(),
            platform: std::env::consts::OS.into(),
            arch: std::env::consts::ARCH.into(),
            kernel: std::fs::read_to_string("/proc/sys/kernel/osrelease")
                .ok()
                .map(|s| s.trim().to_string()),
            started_at,
            duration_ms,
            exit,
            backend,
        },
        environment,
        process_tree: tree,
        events,
        observations: analysis.observations,
        facts: analysis.facts,
        graph: analysis.graph,
        investigations: analysis.investigations,
        hypotheses: analysis.hypotheses,
        conclusion: analysis.conclusion,
        stats,
        redactions: Default::default(),
        diagnostics,
    }
}
