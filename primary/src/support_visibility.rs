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
#[allow(dead_code)]
const MAX_GENERATED_SUPPORT: usize = 6;

/// Receiver-side visibility attack against one wave leader at a time.
///
/// Attack strength is independent of coverage:
/// - proposer always receives every certificate;
/// - consensus sees at most the 3 lowest-index observation-layer supporters
///   until `delay`, once generated support is at least 4;
/// - extras stay held even if generated support later exceeds 6 or reaches coverage.
///
/// Next-layer (leader+2) certificates are never held. Kappa=2's wave-start
/// check looks at the observation layer and misses the extras; kappa=3's check
/// looks at the extra layer, which is not held.
///
/// Only one leader is under hold at a time, so kappa=2 can still commit on
/// the *next* wave after missing the current one.
#[derive(Clone, Debug)]
pub struct SupportVisibilityGate {
    layers: HashMap<Round, LayerView>,
    active_hold_leader: Option<Round>,
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
            active_hold_leader: None,
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
                        let first = layer.next_layer_supporters.is_empty();
                        layer.next_layer_supporters.insert(certificate.origin());
                        if first || layer.next_layer_supporters.len() == MIN_GENERATED_SUPPORT {
                            info!(
                                "SUPPORT_VISIBILITY extra layer inherited leader_round={} extra_layer_support={} extras still delayed",
                                leader_round,
                                layer.next_layer_supporters.len()
                            );
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

        // Park every observation-layer supporter until take_decided can pick a
        // stable lowest-3 set. Delivering "current immediate" on arrival lets
        // high-index certs leak into consensus before lower-index ones appear.
        let author = certificate.origin();
        layer.deferred.insert(author, certificate.clone());
        info!(
            "SUPPORT_VISIBILITY park leader_round={} author_index={:?} generated_support={} delay_ms={}",
            leader_round,
            committee.authority_index(&author),
            Self::generated_supporters(layer).len(),
            delay.as_millis()
        );
        VisibilityAction::Park
    }

    pub fn mark_delivered(&mut self, certificate: &Certificate) {
        let Some(leader_round) = certificate.round().checked_sub(1) else {
            return;
        };
        let clear_hold = if let Some(layer) = self.layers.get_mut(&leader_round) {
            layer.deferred.remove(&certificate.origin());
            layer.delay_armed.remove(&certificate.origin());
            layer.delivered.insert(certificate.origin());
            self.active_hold_leader == Some(leader_round)
                && layer.deferred.is_empty()
                && layer.delay_armed.is_empty()
        } else {
            false
        };
        if clear_hold {
            info!(
                "SUPPORT_VISIBILITY release hold leader_round={}",
                leader_round
            );
            self.active_hold_leader = None;
        }
    }

    fn release_deferred(layer: &mut LayerView, immediate: &mut Vec<Certificate>) {
        for (author, cert) in layer.deferred.drain() {
            if !layer.delay_armed.contains(&author) {
                immediate.push(cert);
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
        let mut leader_rounds: Vec<Round> = self.layers.keys().copied().collect();
        leader_rounds.sort_unstable();
        for leader_round in leader_rounds {
            let generated = self
                .layers
                .get(&leader_round)
                .map(Self::generated_supporters)
                .map(|supporters| supporters.len())
                .unwrap_or(0);
            let layer_size = self
                .layers
                .get(&leader_round)
                .map(|layer| layer.arrived.len())
                .unwrap_or(0);
            if generated < MIN_GENERATED_SUPPORT {
                // Not an attack case: too few supporters were generated.
                // Coverage must not decide this — wait until the layer is full.
                if layer_size >= committee.size() {
                    if let Some(layer) = self.layers.get_mut(&leader_round) {
                        Self::release_deferred(layer, &mut immediate);
                    }
                }
                continue;
            }

            let active = self.active_hold_leader;
            match active {
                Some(active_round) if active_round != leader_round => {
                    // Another leader is already under hold. Leave this
                    // observation layer fully visible so kappa=2 can still
                    // commit on the next wave.
                    info!(
                        "SUPPORT_VISIBILITY skip leader_round={} active_hold={} generated_support={}",
                        leader_round, active_round, generated
                    );
                    if let Some(layer) = self.layers.get_mut(&leader_round) {
                        Self::release_deferred(layer, &mut immediate);
                    }
                    continue;
                }
                None => {
                    self.active_hold_leader = Some(leader_round);
                    info!(
                        "SUPPORT_VISIBILITY arm leader_round={} generated_support={} immediate={} coverage_ignored={}",
                        leader_round,
                        generated,
                        MAX_IMMEDIATE_SUPPORT,
                        committee.coverage
                    );
                }
                Some(_) => {}
            }

            let Some(layer) = self.layers.get_mut(&leader_round) else {
                continue;
            };
            let supporters = Self::generated_supporters(layer);
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
                    "SUPPORT_VISIBILITY hold leader_round={} generated_support={} visible={} delayed={} delay_ms={}",
                    leader_round,
                    generated,
                    MAX_IMMEDIATE_SUPPORT,
                    newly_armed,
                    delay.as_millis()
                );
            }
        }
        (immediate, delayed)
    }

    #[allow(dead_code)]
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
        SupportVisibilityGate, VisibilityAction, MAX_IMMEDIATE_SUPPORT, MAX_GENERATED_SUPPORT,
        MIN_GENERATED_SUPPORT,
    };
    use crate::messages::{Certificate, Header};
    use crypto::Hash as _;
    use crypto::PublicKey;
    use std::collections::HashSet;
    use std::time::Duration;

    fn supporter_set(indices: &[usize], names: &[crypto::PublicKey]) -> HashSet<crypto::PublicKey> {
        indices.iter().map(|index| names[*index]).collect()
    }

    fn attack_committee() -> config::Committee {
        let mut committee = crate::common::committee();
        committee.attack_support_visibility = true;
        committee.sigma = 1;
        committee.kappa = 2;
        committee.coverage = 3;
        committee
    }

    fn cert(author: PublicKey, round: u64, wave: HashSet<crypto::Digest>) -> Certificate {
        Certificate {
            header: Header {
                author,
                round,
                solid_wave_vertices: wave,
                ..Header::default()
            },
            ..Certificate::default()
        }
    }

    fn names(committee: &config::Committee) -> Vec<PublicKey> {
        committee.authorities.keys().copied().collect()
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

    #[test]
    fn high_index_first_still_holds_all_but_lowest_three() {
        let committee = attack_committee();
        let names = names(&committee);
        let leader = SupportVisibilityGate::leader_of_round(&committee, 1).unwrap();
        let leader_cert = cert(leader, 1, HashSet::new());
        let wave = HashSet::from([leader_cert.header.id.clone(), leader_cert.digest()]);
        let delay = Duration::from_millis(200);
        let mut gate = SupportVisibilityGate::new();

        assert_eq!(
            gate.action(&leader_cert, &committee, delay),
            VisibilityAction::Deliver
        );

        // Arrive high-index first so the old "current immediate" rule would leak them.
        for author in names.iter().rev() {
            let support = cert(*author, 2, wave.clone());
            assert_eq!(
                gate.action(&support, &committee, delay),
                VisibilityAction::Park
            );
        }

        let (immediate, delayed) = gate.take_decided(&committee, delay);
        assert_eq!(immediate.len(), MAX_IMMEDIATE_SUPPORT);
        assert_eq!(delayed.len(), 1);
        let immediate_authors: HashSet<_> = immediate.iter().map(|c| c.origin()).collect();
        assert!(immediate_authors.contains(&names[0]));
        assert!(immediate_authors.contains(&names[1]));
        assert!(immediate_authors.contains(&names[2]));
        assert_eq!(delayed[0].origin(), names[3]);
        // Coverage is 3; extras must still be held once generated >= 4.
        assert!(committee.coverage < names.len());
    }

    #[test]
    fn extra_layer_is_never_held() {
        let committee = attack_committee();
        let leader = SupportVisibilityGate::leader_of_round(&committee, 1).unwrap();
        let leader_cert = cert(leader, 1, HashSet::new());
        let wave = HashSet::from([leader_cert.header.id.clone(), leader_cert.digest()]);
        let delay = Duration::from_millis(200);
        let mut gate = SupportVisibilityGate::new();
        gate.action(&leader_cert, &committee, delay);

        let extra = cert(names(&committee)[0], 3, wave);
        assert_eq!(
            gate.action(&extra, &committee, delay),
            VisibilityAction::Deliver
        );
        let (immediate, delayed) = gate.take_decided(&committee, delay);
        assert!(immediate.is_empty());
        assert!(delayed.is_empty());
    }

    #[test]
    fn one_leader_at_a_time_leaves_next_observation_visible() {
        let committee = attack_committee();
        let names = names(&committee);
        let delay = Duration::from_millis(200);
        let mut gate = SupportVisibilityGate::new();

        let leader_1 = SupportVisibilityGate::leader_of_round(&committee, 1).unwrap();
        let leader_1_cert = cert(leader_1, 1, HashSet::new());
        let wave_1 = HashSet::from([leader_1_cert.header.id.clone(), leader_1_cert.digest()]);
        gate.action(&leader_1_cert, &committee, delay);
        for author in &names {
            let support = cert(*author, 2, wave_1.clone());
            gate.action(&support, &committee, delay);
        }
        let (_immediate, delayed) = gate.take_decided(&committee, delay);
        assert_eq!(delayed.len(), 1);
        assert_eq!(gate.active_hold_leader, Some(1));

        let leader_3 = SupportVisibilityGate::leader_of_round(&committee, 3).unwrap();
        let leader_3_cert = cert(leader_3, 3, HashSet::new());
        let wave_3 = HashSet::from([leader_3_cert.header.id.clone(), leader_3_cert.digest()]);
        gate.action(&leader_3_cert, &committee, delay);
        for author in &names {
            let support = cert(*author, 4, wave_3.clone());
            assert_eq!(
                gate.action(&support, &committee, delay),
                VisibilityAction::Park
            );
        }
        let (immediate_next, delayed_next) = gate.take_decided(&committee, delay);
        assert!(delayed_next.is_empty(), "next wave observation must not be held");
        assert_eq!(immediate_next.len(), names.len());
    }
}
