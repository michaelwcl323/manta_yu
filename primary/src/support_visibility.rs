// Copyright(C) Facebook, Inc. and its affiliates.
use crate::messages::Certificate;
use crate::primary::Round;
use config::Committee;
use crypto::Hash as _;
use crypto::{Digest, PublicKey};
use log::info;
use std::collections::{HashMap, HashSet};
use std::time::Duration;

const MAX_IMMEDIATE_SUPPORT: usize = 3;
const MIN_GENERATED_SUPPORT: usize = 4;
const MAX_GENERATED_SUPPORT: usize = 6;

/// Receiver-side visibility attack against one wave leader at a time.
///
/// Observation-layer support certificates:
/// - the 3 lowest-index *known* supporters are delivered immediately so coverage
///   can advance and commit checks see at most those 3;
/// - further supporters are parked until the generated count is known;
/// - 4..=6 generated supporters: extras stay held for `delay`;
/// - otherwise extras are released immediately.
///
/// Next-layer certificates are never held. When that layer shows `coverage`
/// distinct supporters, the candidate is released.
#[derive(Clone, Debug)]
pub struct SupportVisibilityGate {
    layers: HashMap<Round, LayerView>,
}

#[derive(Clone, Debug)]
struct LayerView {
    leader_round: Round,
    leader_header_id: Option<Digest>,
    leader_digest: Option<Digest>,
    arrived: HashMap<PublicKey, Certificate>,
    deferred: HashMap<PublicKey, Certificate>,
    delivered: HashSet<PublicKey>,
    next_layer_supporters: HashSet<PublicKey>,
    delay_armed: HashSet<PublicKey>,
    stopped: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VisibilityAction {
    Deliver,
    Park,
}

impl SupportVisibilityGate {
    pub fn new() -> Self {
        Self {
            layers: HashMap::new(),
        }
    }

    pub fn leader_of_round(committee: &Committee, round: Round) -> Option<PublicKey> {
        let mut names: Vec<_> = committee.authorities.keys().copied().collect();
        if names.is_empty() {
            return None;
        }
        names.sort();
        Some(names[round as usize % names.len()])
    }

    pub fn is_leader_round(committee: &Committee, round: Round) -> bool {
        round == 1 || committee.is_solid_wave(round)
    }

    fn layer_mut(&mut self, leader_round: Round) -> &mut LayerView {
        self.layers.entry(leader_round).or_insert_with(|| LayerView {
            leader_round,
            leader_header_id: None,
            leader_digest: None,
            arrived: HashMap::new(),
            deferred: HashMap::new(),
            delivered: HashSet::new(),
            next_layer_supporters: HashSet::new(),
            delay_armed: HashSet::new(),
            stopped: false,
        })
    }

    fn certificate_supports(cert: &Certificate, leader_header_id: &Digest, leader_digest: &Digest) -> bool {
        cert.header.solid_wave_vertices.contains(leader_header_id)
            || cert.header.solid_wave_vertices.contains(leader_digest)
    }

    fn supporter_indices(committee: &Committee, supporters: &HashSet<PublicKey>) -> Vec<usize> {
        let mut indices: Vec<_> = supporters
            .iter()
            .filter_map(|name| committee.authority_index(name))
            .collect();
        indices.sort_unstable();
        indices
    }

    fn is_immediate_supporter(committee: &Committee, author: &PublicKey, supporters: &HashSet<PublicKey>) -> bool {
        let Some(index) = committee.authority_index(author) else {
            return false;
        };
        Self::supporter_indices(committee, supporters)
            .into_iter()
            .take(MAX_IMMEDIATE_SUPPORT)
            .any(|immediate| immediate == index)
    }

    fn generated_supporters(layer: &LayerView) -> HashSet<PublicKey> {
        let (Some(header_id), Some(digest)) = (&layer.leader_header_id, &layer.leader_digest) else {
            return HashSet::new();
        };
        layer
            .arrived
            .iter()
            .filter(|(_, cert)| Self::certificate_supports(cert, header_id, digest))
            .map(|(author, _)| *author)
            .collect()
    }

    pub fn note_certificate(&mut self, certificate: &Certificate, committee: &Committee) {
        let round = certificate.round();
        if Self::is_leader_round(committee, round) {
            if let Some(leader) = Self::leader_of_round(committee, round) {
                if certificate.origin() == leader {
                    let layer = self.layer_mut(round);
                    layer.leader_header_id = Some(certificate.header.id.clone());
                    layer.leader_digest = Some(certificate.digest());
                }
            }
        }

        if let Some(leader_round) = round.checked_sub(1) {
            if Self::is_leader_round(committee, leader_round) {
                let layer = self.layer_mut(leader_round);
                layer.arrived.insert(certificate.origin(), certificate.clone());
            }
        }

        if let Some(leader_round) = round.checked_sub(2) {
            if Self::is_leader_round(committee, leader_round) {
                let layer = self.layer_mut(leader_round);
                if let (Some(header_id), Some(digest)) =
                    (layer.leader_header_id.clone(), layer.leader_digest.clone())
                {
                    if Self::certificate_supports(certificate, &header_id, &digest) {
                        layer.next_layer_supporters.insert(certificate.origin());
                        if layer.next_layer_supporters.len() >= committee.coverage {
                            if !layer.stopped {
                                info!(
                                    "SUPPORT_VISIBILITY stop candidate leader_round={} next_layer_supporters={} coverage={}",
                                    leader_round,
                                    layer.next_layer_supporters.len(),
                                    committee.coverage
                                );
                            }
                            layer.stopped = true;
                        }
                    }
                }
            }
        }
    }

    pub fn action(
        &mut self,
        certificate: &Certificate,
        committee: &Committee,
        delay: Duration,
    ) -> VisibilityAction {
        if !committee.attack_support_visibility || delay.is_zero() {
            return VisibilityAction::Deliver;
        }
        self.note_certificate(certificate, committee);
        let round = certificate.round();
        let Some(leader_round) = round.checked_sub(1) else {
            return VisibilityAction::Deliver;
        };
        if !Self::is_leader_round(committee, leader_round) {
            return VisibilityAction::Deliver;
        }
        let layer = self.layer_mut(leader_round);
        if layer.stopped || layer.delivered.contains(&certificate.origin()) {
            return VisibilityAction::Deliver;
        }
        if layer.deferred.contains_key(&certificate.origin()) {
            return VisibilityAction::Park;
        }
        let (Some(header_id), Some(digest)) =
            (layer.leader_header_id.clone(), layer.leader_digest.clone())
        else {
            return VisibilityAction::Deliver;
        };
        if !Self::certificate_supports(certificate, &header_id, &digest) {
            return VisibilityAction::Deliver;
        }

        let supporters = Self::generated_supporters(layer);
        if Self::is_immediate_supporter(committee, &certificate.origin(), &supporters) {
            return VisibilityAction::Deliver;
        }

        let author = certificate.origin();
        layer.deferred.insert(author, certificate.clone());
        info!(
            "SUPPORT_VISIBILITY hold leader_round={} author_index={:?} generated_support={} immediate={} delay_ms={}",
            leader_round,
            committee.authority_index(&author),
            supporters.len(),
            MAX_IMMEDIATE_SUPPORT,
            delay.as_millis()
        );
        VisibilityAction::Park
    }

    pub fn mark_delivered(&mut self, certificate: &Certificate) {
        if let Some(leader_round) = certificate.round().checked_sub(1) {
            if let Some(layer) = self.layers.get_mut(&leader_round) {
                layer.deferred.remove(&certificate.origin());
                layer.delay_armed.remove(&certificate.origin());
                layer.delivered.insert(certificate.origin());
            }
        }
    }

    pub fn take_decided(
        &mut self,
        committee: &Committee,
        delay: Duration,
    ) -> (Vec<Certificate>, Vec<Certificate>) {
        let mut immediate = Vec::new();
        let mut delayed = Vec::new();
        for layer in self.layers.values_mut() {
            if layer.stopped {
                for (author, cert) in layer.deferred.drain() {
                    if !layer.delay_armed.contains(&author) {
                        immediate.push(cert);
                    }
                }
                continue;
            }
            let supporters = Self::generated_supporters(layer);
            let generated = supporters.len();
            let layer_size = layer.arrived.len();
            if generated >= committee.coverage || generated > MAX_GENERATED_SUPPORT {
                for (author, cert) in layer.deferred.drain() {
                    if !layer.delay_armed.contains(&author) {
                        immediate.push(cert);
                    }
                }
                continue;
            }
            if generated < MIN_GENERATED_SUPPORT {
                if layer_size >= committee.size() || layer_size >= committee.coverage {
                    for (author, cert) in layer.deferred.drain() {
                        if !layer.delay_armed.contains(&author) {
                            immediate.push(cert);
                        }
                    }
                }
                continue;
            }
            let delay_armed = layer.delay_armed.clone();
            let mut extras = Vec::new();
            layer.deferred.retain(|author, cert| {
                if Self::is_immediate_supporter(committee, author, &supporters) {
                    if !delay_armed.contains(author) {
                        immediate.push(cert.clone());
                    }
                    false
                } else {
                    extras.push((*author, cert.clone()));
                    true
                }
            });
            let mut newly_armed = 0usize;
            for (author, cert) in extras {
                if layer.delay_armed.insert(author) {
                    newly_armed += 1;
                    delayed.push(cert);
                }
            }
            if newly_armed > 0 {
                info!(
                    "SUPPORT_VISIBILITY hold leader_round={} generated_support={} delayed={} delay_ms={}",
                    layer.leader_round,
                    generated,
                    newly_armed,
                    delay.as_millis()
                );
            }
        }
        (immediate, delayed)
    }

    pub fn sync_delay_ms(&self, certificate: &Certificate, committee: &Committee, delay_ms: u64) -> u64 {
        if !committee.attack_support_visibility || delay_ms == 0 {
            return 0;
        }
        let Some(leader_round) = certificate.round().checked_sub(1) else {
            return 0;
        };
        let Some(layer) = self.layers.get(&leader_round) else {
            return 0;
        };
        if layer.stopped {
            return 0;
        }
        if layer.deferred.contains_key(&certificate.origin())
            || layer.delay_armed.contains(&certificate.origin())
        {
            return delay_ms;
        }
        0
    }
}

impl Default for SupportVisibilityGate {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SupportVisibilityGate, MAX_GENERATED_SUPPORT, MAX_IMMEDIATE_SUPPORT, MIN_GENERATED_SUPPORT,
    };
    use std::collections::HashSet;

    fn supporter_set(indices: &[usize], names: &[crypto::PublicKey]) -> HashSet<crypto::PublicKey> {
        indices.iter().map(|index| names[*index]).collect()
    }

    #[test]
    fn four_supporters_keep_three_lowest_index_immediate() {
        let committee = crate::common::committee();
        let names: Vec<_> = committee.authorities.keys().copied().collect();
        assert_eq!(names.len(), 4);
        let supporters = supporter_set(&[0, 1, 2, 3], &names);
        assert_eq!(supporters.len(), MIN_GENERATED_SUPPORT);
        assert!(supporters.len() <= MAX_GENERATED_SUPPORT);
        assert!(SupportVisibilityGate::is_immediate_supporter(
            &committee,
            &names[0],
            &supporters
        ));
        assert!(SupportVisibilityGate::is_immediate_supporter(
            &committee,
            &names[2],
            &supporters
        ));
        assert!(!SupportVisibilityGate::is_immediate_supporter(
            &committee,
            &names[3],
            &supporters
        ));
        assert_eq!(MAX_IMMEDIATE_SUPPORT, 3);
    }

    #[test]
    fn leader_of_round_is_round_robin_in_key_order() {
        let committee = crate::common::committee();
        let names: Vec<_> = committee.authorities.keys().copied().collect();
        assert_eq!(
            SupportVisibilityGate::leader_of_round(&committee, 1),
            Some(names[1 % names.len()])
        );
        assert_eq!(
            SupportVisibilityGate::leader_of_round(&committee, 5),
            Some(names[5 % names.len()])
        );
    }
}
