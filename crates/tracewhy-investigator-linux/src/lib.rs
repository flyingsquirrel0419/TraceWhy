//! Linux investigators. They only read system state; none of them changes it.

pub mod elf;
mod fs;
mod net;
mod path;
mod port;
mod sys;

pub use elf::{parse_elf, ElfSummary};

use tracewhy_core::{
    FactKind, InvestigationContext, InvestigationCost, InvestigationError, InvestigationTarget,
    Investigator,
};

/// All Linux investigators, in a stable order.
pub fn investigators() -> Vec<Box<dyn Investigator>> {
    vec![
        Box::new(PortInvestigator),
        Box::new(PathInvestigator),
        Box::new(ExecutableInvestigator),
        Box::new(FilesystemInvestigator),
        Box::new(ElfInvestigator),
        Box::new(LibraryInvestigator),
        Box::new(DnsInvestigator),
        Box::new(NetworkInvestigator),
        Box::new(FdLimitInvestigator),
        Box::new(PrivilegesInvestigator),
    ]
}

macro_rules! cheap {
    () => {
        fn cost(&self, _t: &InvestigationTarget) -> InvestigationCost {
            InvestigationCost::CHEAP
        }
    };
}

/// Who listens on a TCP port (from /proc/net/tcp{,6} and /proc/*/fd).
pub struct PortInvestigator;
impl Investigator for PortInvestigator {
    fn id(&self) -> &'static str {
        "port"
    }
    fn supports(&self, t: &InvestigationTarget) -> bool {
        matches!(t, InvestigationTarget::Port { .. })
    }
    fn cost(&self, _t: &InvestigationTarget) -> InvestigationCost {
        InvestigationCost {
            expected_millis: 20,
            external_process: false,
        }
    }
    fn investigate(
        &self,
        ctx: &InvestigationContext<'_>,
    ) -> Result<Vec<FactKind>, InvestigationError> {
        let InvestigationTarget::Port { port, .. } = ctx.target else {
            return Ok(Vec::new());
        };
        port::listeners(*port, ctx.deadline).map(|listeners| {
            vec![FactKind::PortListeners {
                port: *port,
                listeners,
            }]
        })
    }
}

/// Existence, type, permissions and ownership of a path and its parents.
pub struct PathInvestigator;
impl Investigator for PathInvestigator {
    fn id(&self) -> &'static str {
        "path"
    }
    fn supports(&self, t: &InvestigationTarget) -> bool {
        matches!(t, InvestigationTarget::Path { .. })
    }
    cheap!();
    fn investigate(
        &self,
        ctx: &InvestigationContext<'_>,
    ) -> Result<Vec<FactKind>, InvestigationError> {
        let InvestigationTarget::Path { path } = ctx.target else {
            return Ok(Vec::new());
        };
        Ok(path::investigate_path(path, ctx.env))
    }
}

/// Where (and whether) a command name resolves on PATH.
pub struct ExecutableInvestigator;
impl Investigator for ExecutableInvestigator {
    fn id(&self) -> &'static str {
        "executable"
    }
    fn supports(&self, t: &InvestigationTarget) -> bool {
        matches!(t, InvestigationTarget::Executable { .. })
    }
    cheap!();
    fn investigate(
        &self,
        ctx: &InvestigationContext<'_>,
    ) -> Result<Vec<FactKind>, InvestigationError> {
        let InvestigationTarget::Executable { name } = ctx.target else {
            return Ok(Vec::new());
        };
        Ok(path::search_executable(name, ctx.env, &ctx.cwd))
    }
}

/// Free space, inodes and mount flags of the filesystem holding a path.
pub struct FilesystemInvestigator;
impl Investigator for FilesystemInvestigator {
    fn id(&self) -> &'static str {
        "filesystem"
    }
    fn supports(&self, t: &InvestigationTarget) -> bool {
        matches!(t, InvestigationTarget::Filesystem { .. })
    }
    cheap!();
    fn investigate(
        &self,
        ctx: &InvestigationContext<'_>,
    ) -> Result<Vec<FactKind>, InvestigationError> {
        let InvestigationTarget::Filesystem { path } = ctx.target else {
            return Ok(Vec::new());
        };
        fs::filesystem(path).map(|f| vec![f])
    }
}

/// ELF header, loader and architecture of an executable.
pub struct ElfInvestigator;
impl Investigator for ElfInvestigator {
    fn id(&self) -> &'static str {
        "elf"
    }
    fn supports(&self, t: &InvestigationTarget) -> bool {
        matches!(t, InvestigationTarget::Elf { .. })
    }
    cheap!();
    fn investigate(
        &self,
        ctx: &InvestigationContext<'_>,
    ) -> Result<Vec<FactKind>, InvestigationError> {
        let InvestigationTarget::Elf { path } = ctx.target else {
            return Ok(Vec::new());
        };
        Ok(elf::investigate(path, ctx.env))
    }
}

/// Where the dynamic loader would (and could) find a shared library.
pub struct LibraryInvestigator;
impl Investigator for LibraryInvestigator {
    fn id(&self) -> &'static str {
        "library"
    }
    fn supports(&self, t: &InvestigationTarget) -> bool {
        matches!(t, InvestigationTarget::Library { .. })
    }
    fn cost(&self, _t: &InvestigationTarget) -> InvestigationCost {
        InvestigationCost {
            expected_millis: 50,
            external_process: false,
        }
    }
    fn investigate(
        &self,
        ctx: &InvestigationContext<'_>,
    ) -> Result<Vec<FactKind>, InvestigationError> {
        let InvestigationTarget::Library { name, executable } = ctx.target else {
            return Ok(Vec::new());
        };
        Ok(elf::search_library(
            name,
            executable.as_deref(),
            ctx.env,
            &ctx.cwd,
            ctx.deadline,
        ))
    }
}

/// Whether a hostname resolves now, and the resolver configuration.
pub struct DnsInvestigator;
impl Investigator for DnsInvestigator {
    fn id(&self) -> &'static str {
        "dns"
    }
    fn supports(&self, t: &InvestigationTarget) -> bool {
        matches!(t, InvestigationTarget::Hostname { .. })
    }
    fn cost(&self, _t: &InvestigationTarget) -> InvestigationCost {
        InvestigationCost {
            expected_millis: 100,
            external_process: false,
        }
    }
    fn investigate(
        &self,
        ctx: &InvestigationContext<'_>,
    ) -> Result<Vec<FactKind>, InvestigationError> {
        let InvestigationTarget::Hostname { name } = ctx.target else {
            return Ok(Vec::new());
        };
        net::resolve(name, ctx.time_left())
    }
}

/// Local interface addresses and default routes.
pub struct NetworkInvestigator;
impl Investigator for NetworkInvestigator {
    fn id(&self) -> &'static str {
        "network"
    }
    fn supports(&self, t: &InvestigationTarget) -> bool {
        matches!(t, InvestigationTarget::Network)
    }
    cheap!();
    fn investigate(
        &self,
        _ctx: &InvestigationContext<'_>,
    ) -> Result<Vec<FactKind>, InvestigationError> {
        Ok(net::network())
    }
}

/// The open-file limit the traced command inherited.
pub struct FdLimitInvestigator;
impl Investigator for FdLimitInvestigator {
    fn id(&self) -> &'static str {
        "fd_limit"
    }
    fn supports(&self, t: &InvestigationTarget) -> bool {
        matches!(t, InvestigationTarget::FdLimit)
    }
    cheap!();
    fn investigate(
        &self,
        _ctx: &InvestigationContext<'_>,
    ) -> Result<Vec<FactKind>, InvestigationError> {
        let (soft, hard) = sys::nofile_limit()
            .ok_or_else(|| InvestigationError::Failed("getrlimit failed".into()))?;
        Ok(vec![FactKind::FdLimit { soft, hard }])
    }
}

/// Effective uid, CAP_NET_BIND_SERVICE and the unprivileged-port threshold.
pub struct PrivilegesInvestigator;
impl Investigator for PrivilegesInvestigator {
    fn id(&self) -> &'static str {
        "privileges"
    }
    fn supports(&self, t: &InvestigationTarget) -> bool {
        matches!(t, InvestigationTarget::Privileges { .. })
    }
    cheap!();
    fn investigate(
        &self,
        ctx: &InvestigationContext<'_>,
    ) -> Result<Vec<FactKind>, InvestigationError> {
        let exe = match ctx.target {
            InvestigationTarget::Privileges { executable } => executable.as_deref(),
            _ => None,
        };
        Ok(sys::privileges(exe))
    }
}
