// Copyright(C) Facebook, Inc. and its affiliates.
use crypto::{generate_production_keypair, PublicKey, SecretKey};
use log::info;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, OpenOptions};
use std::io::BufWriter;
use std::io::Write as _;
use std::net::SocketAddr;
use thiserror::Error;

fn default_allow_cross_step_weak_edges() -> bool {
    true
}

fn default_enable_fast_coin() -> bool {
    false
}

fn default_enable_commit_recheck() -> bool {
    true
}

fn default_fast_coin_candidate_threshold() -> usize {
    0
}

fn default_solid_candidate_threshold() -> usize {
    0
}

fn default_attack_enabled() -> bool {
    false
}

fn default_attack_start_secs() -> u64 {
    0
}

fn default_attack_duration_secs() -> u64 {
    0
}

fn default_attack_group_size() -> usize {
    0
}

fn default_attack_limit_headers() -> bool {
    false
}

fn default_attack_limit_certificates() -> bool {
    true
}

fn default_enable_adaptive_intermediate_spill() -> bool {
    false
}

fn default_adaptive_intermediate_spill_trigger_digests() -> usize {
    2
}

fn default_adaptive_intermediate_spill_cap_digests() -> usize {
    1
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Node {0} is not in the committee")]
    NotInCommittee(PublicKey),

    #[error("Unknown worker id {0}")]
    UnknownWorker(WorkerId),

    #[error("Failed to read config file '{file}': {message}")]
    ImportError { file: String, message: String },

    #[error("Failed to write config file '{file}': {message}")]
    ExportError { file: String, message: String },
}

pub trait Import: DeserializeOwned {
    fn import(path: &str) -> Result<Self, ConfigError> {
        let reader = || -> Result<Self, std::io::Error> {
            let data = fs::read(path)?;
            Ok(serde_json::from_slice(data.as_slice())?)
        };
        reader().map_err(|e| ConfigError::ImportError {
            file: path.to_string(),
            message: e.to_string(),
        })
    }
}

pub trait Export: Serialize {
    fn export(&self, path: &str) -> Result<(), ConfigError> {
        let writer = || -> Result<(), std::io::Error> {
            let file = OpenOptions::new().create(true).write(true).open(path)?;
            let mut writer = BufWriter::new(file);
            let data = serde_json::to_string_pretty(self).unwrap();
            writer.write_all(data.as_ref())?;
            writer.write_all(b"\n")?;
            Ok(())
        };
        writer().map_err(|e| ConfigError::ExportError {
            file: path.to_string(),
            message: e.to_string(),
        })
    }
}

pub type Stake = u32;
pub type WorkerId = u32;

#[derive(Deserialize, Clone)]
pub struct Parameters {
    /// The preferred header size. The primary creates a new header when it has enough parents and
    /// enough batches' digests to reach `header_size`. Denominated in bytes.
    pub header_size: usize,
    /// The maximum delay that the primary waits between generating two headers, even if the header
    /// did not reach `max_header_size`. Denominated in ms.
    pub max_header_delay: u64,
    /// The depth of the garbage collection (Denominated in number of rounds).
    pub gc_depth: u64,
    /// The delay after which the synchronizer retries to send sync requests. Denominated in ms.
    pub sync_retry_delay: u64,
    /// Determine with how many nodes to sync when re-trying to send sync-request. These nodes
    /// are picked at random from the committee.
    pub sync_retry_nodes: usize,
    /// The preferred batch size. The workers seal a batch of transactions when it reaches this size.
    /// Denominated in bytes.
    pub batch_size: usize,
    /// The delay after which the workers seal a batch of transactions, even if `max_batch_size`
    /// is not reached. Denominated in ms.
    pub max_batch_delay: u64,
    /// Whether the proposer should first fill the critical payload queue and only spill a small
    /// amount of new digests into the intermediate queue once the critical backlog is large enough.
    #[serde(default = "default_enable_adaptive_intermediate_spill")]
    pub enable_adaptive_intermediate_spill: bool,
    /// Minimum number of critical-queue digests required before adaptive spill may route new
    /// digests into the intermediate queue.
    #[serde(default = "default_adaptive_intermediate_spill_trigger_digests")]
    pub adaptive_intermediate_spill_trigger_digests: usize,
    /// Maximum number of digests to keep in the intermediate spill window before routing new
    /// digests back to the critical queue.
    #[serde(default = "default_adaptive_intermediate_spill_cap_digests")]
    pub adaptive_intermediate_spill_cap_digests: usize,
}

impl Default for Parameters {
    fn default() -> Self {
        Self {
            header_size: 1_000,
            max_header_delay: 100,
            gc_depth: 50,
            sync_retry_delay: 5_000,
            sync_retry_nodes: 3,
            batch_size: 500_000,
            max_batch_delay: 100,
            enable_adaptive_intermediate_spill: false,
            adaptive_intermediate_spill_trigger_digests: 2,
            adaptive_intermediate_spill_cap_digests: 1,
        }
    }
}

impl Import for Parameters {}

impl Parameters {
    pub fn log(&self) {
        info!("Header size set to {} B", self.header_size);
        info!("Max header delay set to {} ms", self.max_header_delay);
        info!("Garbage collection depth set to {} rounds", self.gc_depth);
        info!("Sync retry delay set to {} ms", self.sync_retry_delay);
        info!("Sync retry nodes set to {} nodes", self.sync_retry_nodes);
        info!("Batch size set to {} B", self.batch_size);
        info!("Max batch delay set to {} ms", self.max_batch_delay);
        info!(
            "Adaptive intermediate spill set to {}",
            self.enable_adaptive_intermediate_spill
        );
        info!(
            "Adaptive intermediate spill trigger set to {} digests",
            self.adaptive_intermediate_spill_trigger_digests
        );
        info!(
            "Adaptive intermediate spill cap set to {} digests",
            self.adaptive_intermediate_spill_cap_digests
        );
    }
}

#[derive(Clone, Deserialize)]
pub struct PrimaryAddresses {
    /// Address to receive messages from other primaries (WAN).
    pub primary_to_primary: SocketAddr,
    /// Address to receive messages from our workers (LAN).
    pub worker_to_primary: SocketAddr,
}

#[derive(Clone, Deserialize, Eq, Hash, PartialEq)]
pub struct WorkerAddresses {
    /// Address to receive client transactions (WAN).
    pub transactions: SocketAddr,
    /// Address to receive messages from other workers (WAN).
    pub worker_to_worker: SocketAddr,
    /// Address to receive messages from our primary (LAN).
    pub primary_to_worker: SocketAddr,
}

#[derive(Clone, Deserialize)]
pub struct Authority {
    /// The voting power of this authority.
    pub stake: Stake,
    /// The network addresses of the primary.
    pub primary: PrimaryAddresses,
    /// Map of workers' id and their network addresses.
    pub workers: HashMap<WorkerId, WorkerAddresses>,
}

#[derive(Clone, Deserialize)]
pub struct Committee {
    pub authorities: BTreeMap<PublicKey, Authority>,
    /// The length of the solid step [r, r+sigma]
    pub sigma: usize,
    /// The number of solid steps in a wave
    pub kappa: usize,
    /// The reference parameter for the solid step.
    pub reference: usize,
    /// The coverage parameter for the solid step.
    pub coverage: usize,
    /// Whether weak parents may extend from the current solid step into earlier
    /// solid steps that are still inside the current solid-wave window.
    #[serde(default = "default_allow_cross_step_weak_edges")]
    pub allow_cross_step_weak_edges: bool,
    /// Whether to enable the fast-coin path, which starts one round earlier
    /// than the regular solid-wave commit check.
    #[serde(default = "default_enable_fast_coin")]
    pub enable_fast_coin: bool,
    /// Whether a pending commit check should be re-evaluated when additional
    /// late support certificates for the same support round arrive.
    #[serde(default = "default_enable_commit_recheck")]
    pub enable_commit_recheck: bool,
    /// Minimum number of leader-round vertices that must each gather f+1 support
    /// on the fast-coin support round before the fast-coin path starts leader selection.
    #[serde(default = "default_fast_coin_candidate_threshold")]
    pub fast_coin_candidate_threshold: usize,
    /// Minimum number of leader-round vertices that must each gather f+1 support
    /// on the regular solid support round before the solid path starts leader selection.
    #[serde(default = "default_solid_candidate_threshold")]
    pub solid_candidate_threshold: usize,
    /// When true, enqueue solid-path commit checks as soon as the round after a solid-step
    /// support round is observed (legacy). When false (default), enqueue when the **first**
    /// certificate in round `solid_wave_length() + 1` arrives (round **5** when σ=κ=2), then the
    /// same for each subsequent wave (9, 13, …); support/leader rounds come from the last
    /// solid-step round inside the wave that just ended.
    #[serde(default)]
    pub solid_commit_trigger_on_solid_step: bool,
    /// Enables the selective-broadcast attack that limits cross-group visibility after a
    /// fixed delay from node startup.
    #[serde(default = "default_attack_enabled")]
    pub attack_enabled: bool,
    /// Delay in seconds before the selective-broadcast attack becomes active.
    #[serde(default = "default_attack_start_secs")]
    pub attack_start_secs: u64,
    /// Attack duration in seconds. Zero means the attack stays enabled until the run ends.
    #[serde(default = "default_attack_duration_secs")]
    pub attack_duration_secs: u64,
    /// Size of the first attack group. When set to 0, split the committee in half.
    #[serde(default = "default_attack_group_size")]
    pub attack_group_size: usize,
    /// Whether to also limit header broadcasts once the attack starts.
    #[serde(default = "default_attack_limit_headers")]
    pub attack_limit_headers: bool,
    /// Whether to limit certificate broadcasts and sync replies once the attack starts.
    #[serde(default = "default_attack_limit_certificates")]
    pub attack_limit_certificates: bool,
}

impl Import for Committee {}

impl Committee {
    /// Returns the number of authorities.
    pub fn size(&self) -> usize {
        self.authorities.len()
    }

    /// Return the stake of a specific authority.
    pub fn stake(&self, name: &PublicKey) -> Stake {
        self.authorities.get(&name).map_or_else(|| 0, |x| x.stake)
    }

    /// Returns the deterministic bitmap index of an authority.
    pub fn authority_index(&self, name: &PublicKey) -> Option<usize> {
        self.authorities.keys().position(|authority| authority == name)
    }

    /// Returns the number of bytes required to store one bit per authority.
    pub fn authority_bitmap_len(&self) -> usize {
        (self.size() + 7) / 8
    }

    /// Returns the stake of all authorities except `myself`.
    pub fn others_stake(&self, myself: &PublicKey) -> Vec<(PublicKey, Stake)> {
        self.authorities
            .iter()
            .filter(|(name, _)| name != &myself)
            .map(|(name, authority)| (*name, authority.stake))
            .collect()
    }

    /// Returns the stake required to reach a quorum (2f+1).
    pub fn quorum_threshold(&self) -> Stake {
        // If N = 3f + 1 + k (0 <= k < 3)
        // then (2 N + 3) / 3 = 2f + 1 + (2k + 2)/3 = 2f + 1 + k = N - f
        let total_votes: Stake = self.authorities.values().map(|x| x.stake).sum();
        2 * total_votes / 3 + 1
        // (total_votes + 2) / 3
    }

    pub fn processing_threshold(&self, current_round: u64) -> Stake {
        // Apart from the quorum threshold, this is specially for processing headers.
        if self.is_solid_step(current_round) {
            return self.coverage as Stake;
            // return (total_votes + 2) / 3;
        } else {
            //
            return self.reference as Stake;
        }
    }

    /// Returns the stake required to reach availability (f+1).
    pub fn validity_threshold(&self) -> Stake {
        // If N = 3f + 1 + k (0 <= k < 3)
        // then (N + 2) / 3 = f + 1 + k/3 = f + 1
        let total_votes: Stake = self.authorities.values().map(|x| x.stake).sum();
        (total_votes + 2) / 3
    }

    pub fn max_threshold(&self) -> Stake {
        self.coverage as Stake
    }

    /// Returns the size of the first attack group. When no explicit split is configured,
    /// split the committee roughly in half. Degenerate committee sizes disable the split.
    pub fn selective_attack_group_size(&self) -> usize {
        let committee_size = self.size();
        match committee_size {
            0 | 1 => committee_size,
            size => {
                let configured = if self.attack_group_size == 0 {
                    size / 2
                } else {
                    self.attack_group_size
                };
                configured.clamp(1, size - 1)
            }
        }
    }

    fn selective_attack_group_bounds(&self, group: usize) -> Option<(usize, usize)> {
        if self.size() <= 1 {
            return None;
        }
        let split = self.selective_attack_group_size();
        match group {
            0 => Some((0, split)),
            1 => Some((split, self.size())),
            _ => None,
        }
    }

    pub fn selective_attack_group(&self, name: &PublicKey) -> Option<usize> {
        let index = self.authority_index(name)?;
        let split = self.selective_attack_group_size();
        Some(usize::from(index >= split))
    }

    fn selective_attack_rank_in_group(&self, name: &PublicKey) -> Option<usize> {
        let index = self.authority_index(name)?;
        let split = self.selective_attack_group_size();
        if index < split {
            Some(index)
        } else {
            Some(index - split)
        }
    }

    fn selective_attack_same_group_remote_sender_limit(&self, recipient: &PublicKey) -> usize {
        let Some(group) = self.selective_attack_group(recipient) else {
            return 0;
        };
        let Some((start, end)) = self.selective_attack_group_bounds(group) else {
            return 0;
        };
        let local_group_size = end.saturating_sub(start);
        self.coverage
            .saturating_sub(1)
            .min(local_group_size.saturating_sub(1))
    }

    /// Returns how many cross-group senders should stay visible to the given recipient once the
    /// attack starts, after reserving the smallest same-group sender set needed to keep the total
    /// visible author set at exactly `coverage` whenever possible.
    pub fn selective_attack_cross_group_sender_limit(&self, recipient: &PublicKey) -> usize {
        let Some(group) = self.selective_attack_group(recipient) else {
            return 0;
        };
        let Some((start, end)) = self.selective_attack_group_bounds(group) else {
            return 0;
        };
        let local_group_size = end.saturating_sub(start);
        let other_group_size = self.size().saturating_sub(local_group_size);
        let same_group_remote_limit = self.selective_attack_same_group_remote_sender_limit(recipient);
        self.coverage
            .saturating_sub(1 + same_group_remote_limit)
            .min(other_group_size)
    }

    fn selective_attack_rank_distance(rank: usize, start: usize, modulo: usize) -> usize {
        if modulo == 0 {
            0
        } else if rank >= start {
            rank - start
        } else {
            modulo - (start - rank)
        }
    }

    /// Receiver-centric selective visibility rule used by the attack. Each recipient sees only the
    /// minimum number of remote authors needed to reach `coverage` once its own author is counted:
    /// first a deterministic rotating prefix of same-group peers, then a deterministic rotating
    /// prefix of cross-group peers. Different recipients therefore keep different neighborhoods
    /// while still seeing at most `coverage` total authors whenever possible.
    pub fn selective_attack_allows_sender_to_recipient(
        &self,
        sender: &PublicKey,
        recipient: &PublicKey,
    ) -> bool {
        let Some(sender_group) = self.selective_attack_group(sender) else {
            return true;
        };
        let Some(recipient_group) = self.selective_attack_group(recipient) else {
            return true;
        };
        let Some(recipient_rank) = self.selective_attack_rank_in_group(recipient) else {
            return true;
        };
        let Some(sender_rank) = self.selective_attack_rank_in_group(sender) else {
            return true;
        };

        if sender_group == recipient_group {
            let same_group_limit =
                self.selective_attack_same_group_remote_sender_limit(recipient);
            if same_group_limit == 0 {
                return false;
            }
            let Some((start, end)) = self.selective_attack_group_bounds(recipient_group) else {
                return true;
            };
            let local_group_size = end.saturating_sub(start);
            let distance =
                Self::selective_attack_rank_distance(sender_rank, recipient_rank, local_group_size);
            return distance > 0 && distance <= same_group_limit;
        }

        let allowed_cross_group_senders =
            self.selective_attack_cross_group_sender_limit(recipient);
        if allowed_cross_group_senders == 0 {
            return false;
        }
        let Some((start, end)) = self.selective_attack_group_bounds(recipient_group) else {
            return true;
        };
        let local_group_size = end.saturating_sub(start);
        let other_group_size = self.size().saturating_sub(local_group_size);
        let cross_group_start = recipient_rank % other_group_size.max(1);
        let distance =
            Self::selective_attack_rank_distance(sender_rank, cross_group_start, other_group_size);
        distance < allowed_cross_group_senders
    }

    /// Returns the primary addresses of the target primary.
    pub fn primary(&self, to: &PublicKey) -> Result<PrimaryAddresses, ConfigError> {
        self.authorities
            .get(to)
            .map(|x| x.primary.clone())
            .ok_or_else(|| ConfigError::NotInCommittee(*to))
    }

    /// Returns the addresses of all primaries except `myself`.
    pub fn others_primaries(&self, myself: &PublicKey) -> Vec<(PublicKey, PrimaryAddresses)> {
        self.authorities
            .iter()
            .filter(|(name, _)| name != &myself)
            .map(|(name, authority)| (*name, authority.primary.clone()))
            .collect()
    }

    /// Returns the addresses of a specific worker (`id`) of a specific authority (`to`).
    pub fn worker(&self, to: &PublicKey, id: &WorkerId) -> Result<WorkerAddresses, ConfigError> {
        self.authorities
            .iter()
            .find(|(name, _)| name == &to)
            .map(|(_, authority)| authority)
            .ok_or_else(|| ConfigError::NotInCommittee(*to))?
            .workers
            .iter()
            .find(|(worker_id, _)| worker_id == &id)
            .map(|(_, worker)| worker.clone())
            .ok_or_else(|| ConfigError::NotInCommittee(*to))
    }

    /// Returns the addresses of all our workers.
    pub fn our_workers(&self, myself: &PublicKey) -> Result<Vec<WorkerAddresses>, ConfigError> {
        self.authorities
            .iter()
            .find(|(name, _)| name == &myself)
            .map(|(_, authority)| authority)
            .ok_or_else(|| ConfigError::NotInCommittee(*myself))?
            .workers
            .values()
            .cloned()
            .map(Ok)
            .collect()
    }

    /// Returns the addresses of all workers with a specific id except the ones of the authority
    /// specified by `myself`.
    pub fn others_workers(
        &self,
        myself: &PublicKey,
        id: &WorkerId,
    ) -> Vec<(PublicKey, WorkerAddresses)> {
        self.authorities
            .iter()
            .filter(|(name, _)| name != &myself)
            .filter_map(|(name, authority)| {
                authority
                    .workers
                    .iter()
                    .find(|(worker_id, _)| worker_id == &id)
                    .map(|(_, addresses)| (*name, addresses.clone()))
            })
            .collect()
    }

    /// Returns the number of the solid wave.
    pub fn solid_wave_length(&self) -> u64 {
        (self.sigma) as u64 * (self.kappa as u64)
    }

    /// Returns the length of the solid step.
    pub fn solid_step_length(&self) -> u64 {
        (self.sigma) as u64
    }

    /// Returns whether the provided round is a solid-step boundary.
    /// Solid steps overlap on their boundary round, so for sigma=2 the
    /// boundaries are 1, 3, 5, ...
    pub fn is_solid_step(&self, round: u64) -> bool {
        round > 1 && (round - 1) % self.solid_step_length() == 0
    }

    /// Returns whether the provided round is a solid-wave boundary.
    /// Solid waves overlap on their boundary round, so for wave length 4 the
    /// boundaries are 1, 5, 9, ...
    pub fn is_solid_wave(&self, round: u64) -> bool {
        round > 1 && (round - 1) % self.solid_wave_length() == 0
    }

    /// True if `round` is the first round of a solid wave **after** the genesis wave
    /// (length [`solid_wave_length`](Self::solid_wave_length)).
    ///
    /// When σ=κ=2, wave length is 4: this is exactly round **5**, then 9, 13, …
    /// Consensus uses this so the **first certificate seen in that round** opens the solid
    /// commit check (not round 4 or round 6).
    pub fn is_first_round_of_second_or_later_solid_wave(&self, round: u64) -> bool {
        let w = self.solid_wave_length();
        w > 0 && round > w && self.is_solid_wave(round)
    }

    fn overlapping_segment_start_before(round: u64, length: u64) -> u64 {
        if round <= 1 {
            0
        } else {
            1 + ((round - 2) / length) * length
        }
    }

    /// Returns the first parent round in the solid step that ends at `round`.
    pub fn solid_step_parent_start(&self, round: u64) -> u64 {
        Self::overlapping_segment_start_before(round, self.solid_step_length())
    }

    /// Returns the first parent round in the solid wave that ends at `round`.
    pub fn solid_wave_parent_start(&self, round: u64) -> u64 {
        Self::overlapping_segment_start_before(round, self.solid_wave_length())
    }

    /// Returns the greatest round `r` in `[low, high]` such that `is_solid_step(r)`, if any.
    pub fn last_solid_step_round_in_closed_range(&self, low: u64, high: u64) -> Option<u64> {
        if low > high {
            return None;
        }
        let mut r = high;
        loop {
            if self.is_solid_step(r) {
                return Some(r);
            }
            if r <= low {
                return None;
            }
            r -= 1;
        }
    }

    /// Returns the first round allowed for weak parents that extend beyond the
    /// current strong-parent round. When cross-step weak edges are disabled, we
    /// clamp the weak-parent window to the current solid step.
    pub fn cross_step_weak_parent_start(&self, round: u64) -> u64 {
        if self.allow_cross_step_weak_edges {
            self.solid_wave_parent_start(round)
        } else {
            self.solid_step_parent_start(round)
        }
    }

    /// Returns the round whose authors should be tracked for indirect back-links
    /// while building `round`.
    pub fn wave_back_link_tracking_round(&self, round: u64) -> Option<u64> {
        if round <= 1 {
            return None;
        }

        let tracked_round = self.solid_wave_boundary_at_or_before(round - 1) + 1;
        (tracked_round < round).then_some(tracked_round)
    }

    /// Returns the round whose reachable authors must satisfy the wave back-link
    /// quorum when validating the provided solid-wave boundary round.
    pub fn wave_back_link_target_round(&self, round: u64) -> Option<u64> {
        self.is_solid_wave(round)
            .then(|| self.wave_back_link_tracking_round(round))
            .flatten()
    }

    /// Returns the solid-wave boundary at or before the provided round.
    pub fn solid_wave_boundary_at_or_before(&self, round: u64) -> u64 {
        if round == 0 {
            0
        } else {
            1 + ((round - 1) / self.solid_wave_length()) * self.solid_wave_length()
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct KeyPair {
    /// The node's public key (and identifier).
    pub name: PublicKey,
    /// The node's secret key.
    pub secret: SecretKey,
}

impl Import for KeyPair {}
impl Export for KeyPair {}

impl KeyPair {
    pub fn new() -> Self {
        let (name, secret) = generate_production_keypair();
        Self { name, secret }
    }
}

impl Default for KeyPair {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{Authority, Committee, PrimaryAddresses};
    use crate::generate_production_keypair;
    use std::collections::{BTreeMap, HashMap};

    fn overlapping_committee() -> Committee {
        Committee {
            authorities: BTreeMap::new(),
            sigma: 2,
            kappa: 2,
            reference: 0,
            coverage: 0,
            allow_cross_step_weak_edges: true,
            enable_fast_coin: false,
            enable_commit_recheck: true,
            fast_coin_candidate_threshold: 0,
            solid_candidate_threshold: 0,
            solid_commit_trigger_on_solid_step: false,
            attack_enabled: false,
            attack_start_secs: 0,
            attack_duration_secs: 0,
            attack_group_size: 0,
            attack_limit_headers: false,
            attack_limit_certificates: true,
        }
    }

    fn attack_committee(size: usize, coverage: usize) -> Committee {
        let mut authorities = BTreeMap::new();
        for _ in 0..size {
            let (name, _) = generate_production_keypair();
            authorities.insert(
                name,
                Authority {
                    stake: 1,
                    primary: PrimaryAddresses {
                        primary_to_primary: "127.0.0.1:0".parse().unwrap(),
                        worker_to_primary: "127.0.0.1:0".parse().unwrap(),
                    },
                    workers: HashMap::new(),
                },
            );
        }

        Committee {
            authorities,
            coverage,
            ..overlapping_committee()
        }
    }

    #[test]
    fn last_solid_step_round_in_closed_range_matches_waves() {
        let committee = overlapping_committee();
        assert_eq!(committee.last_solid_step_round_in_closed_range(1, 4), Some(3));
        assert_eq!(committee.last_solid_step_round_in_closed_range(5, 8), Some(7));
    }

    #[test]
    fn first_round_of_second_or_later_solid_wave_matches_round_five_for_default_wave() {
        let committee = overlapping_committee();
        assert!(!committee.is_first_round_of_second_or_later_solid_wave(4));
        assert!(committee.is_first_round_of_second_or_later_solid_wave(5));
        assert!(!committee.is_first_round_of_second_or_later_solid_wave(6));
        assert!(committee.is_first_round_of_second_or_later_solid_wave(9));
    }

    #[test]
    fn overlapping_boundaries_match_design() {
        let committee = overlapping_committee();

        assert!(!committee.is_solid_step(2));
        assert!(committee.is_solid_step(3));
        assert!(!committee.is_solid_step(4));
        assert!(committee.is_solid_step(5));

        assert!(!committee.is_solid_wave(3));
        assert!(!committee.is_solid_wave(4));
        assert!(committee.is_solid_wave(5));
        assert!(!committee.is_solid_wave(8));
        assert!(committee.is_solid_wave(9));
    }

    #[test]
    fn overlapping_parent_windows_match_design() {
        let committee = overlapping_committee();

        assert_eq!(committee.solid_step_parent_start(2), 1);
        assert_eq!(committee.solid_step_parent_start(3), 1);
        assert_eq!(committee.solid_step_parent_start(4), 3);
        assert_eq!(committee.solid_step_parent_start(5), 3);

        assert_eq!(committee.solid_wave_parent_start(3), 1);
        assert_eq!(committee.solid_wave_parent_start(5), 1);
        assert_eq!(committee.solid_wave_parent_start(6), 5);
        assert_eq!(committee.solid_wave_parent_start(8), 5);
        assert_eq!(committee.solid_wave_parent_start(9), 5);
    }

    #[test]
    fn configurable_cross_step_weak_parent_start() {
        let mut committee = overlapping_committee();
        assert_eq!(committee.cross_step_weak_parent_start(8), 5);

        committee.allow_cross_step_weak_edges = false;
        assert_eq!(committee.cross_step_weak_parent_start(8), 7);
    }

    #[test]
    fn wave_back_link_tracking_round_avoids_self_reference_for_sigma_one_kappa_one() {
        let committee = Committee {
            sigma: 1,
            kappa: 1,
            ..overlapping_committee()
        };

        assert_eq!(committee.wave_back_link_tracking_round(1), None);
        assert_eq!(committee.wave_back_link_tracking_round(2), None);
        assert_eq!(committee.wave_back_link_tracking_round(3), None);
        assert_eq!(committee.wave_back_link_target_round(2), None);
        assert_eq!(committee.wave_back_link_target_round(3), None);
    }

    #[test]
    fn wave_back_link_tracking_round_is_preserved_for_non_degenerate_waves() {
        let sigma_one_kappa_two = Committee {
            sigma: 1,
            kappa: 2,
            ..overlapping_committee()
        };
        assert_eq!(sigma_one_kappa_two.wave_back_link_tracking_round(3), Some(2));
        assert_eq!(sigma_one_kappa_two.wave_back_link_target_round(3), Some(2));

        let sigma_two_kappa_one = Committee {
            sigma: 2,
            kappa: 1,
            ..overlapping_committee()
        };
        assert_eq!(sigma_two_kappa_one.wave_back_link_tracking_round(3), Some(2));
        assert_eq!(sigma_two_kappa_one.wave_back_link_target_round(3), Some(2));
    }

    #[test]
    fn selective_attack_keeps_minimal_total_visibility_and_rotates_cross_group_peers() {
        let committee = attack_committee(10, 7);
        let authorities: Vec<_> = committee.authorities.keys().copied().collect();
        let recipient_a = authorities[0];
        let recipient_b = authorities[1];

        assert_eq!(committee.selective_attack_group_size(), 5);
        assert_eq!(
            committee.selective_attack_same_group_remote_sender_limit(&recipient_a),
            4
        );
        assert_eq!(committee.selective_attack_cross_group_sender_limit(&recipient_a), 2);

        assert!(committee.selective_attack_allows_sender_to_recipient(
            &authorities[1],
            &recipient_a
        ));
        assert!(committee.selective_attack_allows_sender_to_recipient(
            &authorities[5],
            &recipient_a
        ));
        assert!(committee.selective_attack_allows_sender_to_recipient(
            &authorities[6],
            &recipient_a
        ));
        assert!(!committee.selective_attack_allows_sender_to_recipient(
            &authorities[7],
            &recipient_a
        ));

        assert!(committee.selective_attack_allows_sender_to_recipient(
            &authorities[6],
            &recipient_b
        ));
        assert!(committee.selective_attack_allows_sender_to_recipient(
            &authorities[7],
            &recipient_b
        ));
        assert!(!committee.selective_attack_allows_sender_to_recipient(
            &authorities[5],
            &recipient_b
        ));
    }

    #[test]
    fn selective_attack_truncates_same_group_visibility_at_f_plus_one() {
        let committee = attack_committee(10, 4);
        let authorities: Vec<_> = committee.authorities.keys().copied().collect();
        let recipient = authorities[0];

        assert_eq!(
            committee.selective_attack_same_group_remote_sender_limit(&recipient),
            3
        );
        assert_eq!(committee.selective_attack_cross_group_sender_limit(&recipient), 0);
        assert!(committee.selective_attack_allows_sender_to_recipient(
            &authorities[1],
            &recipient
        ));
        assert!(committee.selective_attack_allows_sender_to_recipient(
            &authorities[2],
            &recipient
        ));
        assert!(committee.selective_attack_allows_sender_to_recipient(
            &authorities[3],
            &recipient
        ));
        assert!(!committee.selective_attack_allows_sender_to_recipient(
            &authorities[4],
            &recipient
        ));
        assert!(!committee.selective_attack_allows_sender_to_recipient(
            &authorities[5],
            &recipient
        ));
    }
}
