//! The fact store: deduplicated, append-only facts with typed lookups.

use std::collections::HashMap;
use tracewhy_core::{ComposeService, Fact, FactId, FactKind, FactSource, Freshness, Listener};

#[derive(Debug, Default, Clone)]
pub struct FactStore {
    facts: Vec<Fact>,
    latest: HashMap<String, FactId>,
}

impl FactStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_facts(facts: Vec<Fact>) -> Self {
        let mut s = FactStore::default();
        for f in facts {
            s.latest.insert(f.kind.subject_key(), f.id);
            s.facts.push(f);
        }
        s
    }

    /// Add a fact. Re-adding an identical fact returns the existing id.
    pub fn add(&mut self, kind: FactKind, source: FactSource, freshness: Freshness) -> FactId {
        let key = kind.subject_key();
        if let Some(&id) = self.latest.get(&key) {
            if self
                .facts
                .get(id as usize)
                .map(|f| f.kind == kind)
                .unwrap_or(false)
            {
                return id;
            }
        }
        let confidence = match source {
            FactSource::Trace { .. } => 1.0,
            FactSource::Investigator { .. } | FactSource::Preflight => 0.95,
            FactSource::Adapter { .. } => 0.9,
        };
        let id = self.facts.len() as FactId;
        self.facts.push(Fact {
            id,
            kind,
            source,
            collected_at: now(),
            freshness,
            confidence,
        });
        self.latest.insert(key, id);
        id
    }

    pub fn all(&self) -> &[Fact] {
        &self.facts
    }

    pub fn into_vec(self) -> Vec<Fact> {
        self.facts
    }

    pub fn get(&self, id: FactId) -> Option<&Fact> {
        self.facts.get(id as usize)
    }

    pub fn len(&self) -> usize {
        self.facts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.facts.is_empty()
    }

    fn latest_where<'a>(
        &'a self,
        pred: impl Fn(&FactKind) -> bool + 'a,
    ) -> impl Iterator<Item = &'a Fact> + 'a {
        self.latest
            .values()
            .filter_map(move |id| self.facts.get(*id as usize))
            .filter(move |f| pred(&f.kind))
    }

    pub fn by_key(&self, kind_name: &str, subject: &str) -> Option<&Fact> {
        self.latest
            .get(&format!("{kind_name}:{subject}"))
            .and_then(|id| self.facts.get(*id as usize))
    }

    pub fn port(&self, port: u16) -> Option<(FactId, &[Listener])> {
        let f = self.by_key("port_listeners", &port.to_string())?;
        match &f.kind {
            FactKind::PortListeners { listeners, .. } => Some((f.id, listeners.as_slice())),
            _ => None,
        }
    }

    pub fn path(&self, path: &str) -> Option<&Fact> {
        self.by_key("path_status", path)
    }

    pub fn compose_services(&self) -> Vec<(FactId, String, &ComposeService)> {
        let mut v: Vec<(FactId, String, &ComposeService)> = self
            .latest_where(|k| matches!(k, FactKind::ComposeProject { .. }))
            .flat_map(|f| match &f.kind {
                FactKind::ComposeProject { file, services, .. } => services
                    .iter()
                    .map(|s| (f.id, file.clone(), s))
                    .collect::<Vec<_>>(),
                _ => Vec::new(),
            })
            .collect();
        v.sort_by_key(|x| x.0);
        v
    }

    pub fn container(&self, service: &str) -> Option<&Fact> {
        self.by_key("container_state", service)
    }

    pub fn of_type(&self, name: &str) -> Vec<&Fact> {
        let name = name.to_string();
        let mut v: Vec<&Fact> = self.latest_where(move |k| k.name() == name).collect();
        v.sort_by_key(|f| f.id);
        v
    }

    pub fn first_of(&self, name: &str) -> Option<&Fact> {
        self.of_type(name).into_iter().next()
    }
}

fn now() -> Option<f64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs_f64())
}
