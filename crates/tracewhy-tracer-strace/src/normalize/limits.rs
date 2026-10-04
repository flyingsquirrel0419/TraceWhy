//! Resource limits for normalization.

#[derive(Debug, Clone)]
pub struct NormalizeLimits {
    pub max_events: usize,
    pub max_output_bytes_per_process: usize,
    pub max_diagnostics: usize,
}

impl Default for NormalizeLimits {
    fn default() -> Self {
        NormalizeLimits {
            max_events: 400_000,
            max_output_bytes_per_process: 32 * 1024,
            max_diagnostics: 200,
        }
    }
}
