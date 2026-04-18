// Copyright(C) Facebook, Inc. and its affiliates.
use config::{Committee, Stake};
use crypto::Hash as _;
use crypto::{Digest, PublicKey};
use log::{debug, info, log_enabled, warn};
use primary::{Certificate, Round};
use std::cmp::max;
use std::collections::{HashMap, HashSet};
use tokio::sync::mpsc::{Receiver, Sender};

#[cfg(test)]
#[path = "tests/consensus_tests.rs"]
pub mod consensus_tests;

/// The representation of the DAG in memory.
type DagEntry = (Digest, Certificate);
type Dag = HashMap<Round, HashMap<PublicKey, DagEntry>>;
type DagPosition = (Round, PublicKey);

/// The state that needs to be persisted for crash-recovery.
struct State {
    /// The highest round among all committed certificates. This is used for GC only.
    last_committed_certificate_round: Round,
    /// The round of the last leader whose commit path was accepted.
    last_committed_leader_round: Round,
    // Keeps the last committed round for each authority. This map is used to clean up the dag and
    // ensure we don't commit twice the same certificate.
    last_committed: HashMap<PublicKey, Round>,
    /// Keeps the latest committed certificate (and its parents) for every authority. Anything older
    /// must be regularly cleaned up through the function `update`.
    dag: Dag,
    /// Fast lookup for parent certificate digests.
    certificate_index: HashMap<Digest, DagPosition>,
    /// Fast lookup for both certificate digests and header ids. Used by logging / visualization.
    digest_index: HashMap<Digest, DagPosition>,
}

impl State {
    fn new(genesis: Vec<Certificate>) -> Self {
        let mut state = Self {
            last_committed_certificate_round: 0,
            last_committed_leader_round: 0,
            last_committed: HashMap::new(),
            dag: HashMap::new(),
            certificate_index: HashMap::new(),
            digest_index: HashMap::new(),
        };

        for certificate in genesis {
            state.insert(certificate);
        }

        state.last_committed = state
            .dag
            .get(&0)
            .into_iter()
            .flat_map(|genesis_round| genesis_round.iter())
            .map(|(author, (_, certificate))| (*author, certificate.round()))
            .collect();
        state
    }

    fn insert(&mut self, certificate: Certificate) {
        let round = certificate.round();
        let origin = certificate.origin();
        let certificate_digest = certificate.digest();
        let header_id = certificate.header.id.clone();

        if let Some((old_digest, old_certificate)) = self
            .dag
            .entry(round)
            .or_insert_with(HashMap::new)
            .insert(origin, (certificate_digest.clone(), certificate))
        {
            self.remove_indexes(&old_digest, &old_certificate.header.id);
        }

        let position = (round, origin);
        self.certificate_index
            .insert(certificate_digest.clone(), position);
        self.digest_index
            .insert(certificate_digest.clone(), position);
        self.digest_index.insert(header_id, position);
    }

    fn remove_indexes(&mut self, certificate_digest: &Digest, header_id: &Digest) {
        self.certificate_index.remove(certificate_digest);
        self.digest_index.remove(certificate_digest);
        self.digest_index.remove(header_id);
    }

    fn find_certificate(&self, certificate_digest: &Digest) -> Option<&DagEntry> {
        let (round, author) = self.certificate_index.get(certificate_digest)?;
        self.dag.get(round)?.get(author)
    }

    fn find_digest(&self, digest: &Digest) -> Option<DagPosition> {
        self.digest_index.get(digest).copied()
    }

    /// Update and clean up internal state base on committed certificates.
    fn update(&mut self, certificate: &Certificate, gc_depth: Round) {
        self.last_committed
            .entry(certificate.origin())
            .and_modify(|r| *r = max(*r, certificate.round()))
            .or_insert_with(|| certificate.round());

        let last_committed_certificate_round = *self.last_committed.values().max().unwrap();
        self.last_committed_certificate_round = last_committed_certificate_round;
        let last_committed = &self.last_committed;
        let mut removed = Vec::new();

        self.dag.retain(|round, authorities| {
            let keep_round = *round + gc_depth >= last_committed_certificate_round;

            authorities.retain(|author, (digest, certificate)| {
                let keep_certificate =
                    keep_round && *round >= last_committed.get(author).copied().unwrap_or_default();
                if !keep_certificate {
                    removed.push((digest.clone(), certificate.header.id.clone()));
                }
                keep_certificate
            });

            !authorities.is_empty()
        });

        for (certificate_digest, header_id) in removed {
            self.remove_indexes(&certificate_digest, &header_id);
        }
    }

    fn update_last_committed_leader(&mut self, leader_round: Round) {
        self.last_committed_leader_round = max(self.last_committed_leader_round, leader_round);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommitCheckPath {
    Solid,
    FastCoin,
}

impl CommitCheckPath {
    fn log_label(&self) -> &'static str {
        match self {
            Self::Solid => "solid",
            Self::FastCoin => "fast_coin",
        }
    }

    fn support_basis_label(&self) -> &'static str {
        match self {
            Self::Solid => "solid_wave_vertices",
            Self::FastCoin => "solid_step_vertices_or_parent_path",
        }
    }

    fn sort_key(&self) -> u8 {
        match self {
            Self::FastCoin => 0,
            Self::Solid => 1,
        }
    }
}

#[derive(Debug)]
struct PendingCommitCheck {
    path: CommitCheckPath,
    leader_round: Round,
    support_round: Round,
    /// Whether this pending check still requires the candidate-threshold gate
    /// before leader selection may start. The default wave-start fallback clears
    /// this gate even if an earlier fast path already created the same pending.
    candidate_gate_enabled: bool,
    seen_support_certificate_digests: HashSet<Digest>,
}

impl PendingCommitCheck {
    fn matches(&self, other: &PendingCommitCheck) -> bool {
        self.path == other.path
            && self.leader_round == other.leader_round
            && self.support_round == other.support_round
    }
}

pub struct Consensus {
    /// The committee information.
    committee: Committee,
    /// Authorities in deterministic order for leader election.
    authorities: Vec<PublicKey>,
    /// Cache of authority -> node id used by logs and visualization.
    author_to_node: HashMap<PublicKey, usize>,
    /// The depth of the garbage collector.
    gc_depth: Round,

    /// Receives new certificates from the primary. The primary should send us new certificates only
    /// if it already sent us its whole history.
    rx_primary: Receiver<Certificate>,
    /// Outputs the sequence of ordered certificates to the primary (for cleanup and feedback).
    tx_primary: Sender<Certificate>,
    /// Outputs the sequence of ordered certificates to the application layer.
    tx_output: Sender<Certificate>,

    /// The genesis certificates.
    genesis: Vec<Certificate>,
}

impl Consensus {
    pub fn spawn(
        committee: Committee,
        gc_depth: Round,
        rx_primary: Receiver<Certificate>,
        tx_primary: Sender<Certificate>,
        tx_output: Sender<Certificate>,
    ) {
        let authorities: Vec<_> = committee.authorities.keys().copied().collect();
        let author_to_node = authorities
            .iter()
            .copied()
            .enumerate()
            .map(|(index, authority)| (authority, index))
            .collect();
        tokio::spawn(async move {
            Self {
                committee: committee.clone(),
                authorities,
                author_to_node,
                gc_depth,
                rx_primary,
                tx_primary,
                tx_output,
                genesis: Certificate::genesis(&committee),
            }
            .run()
            .await;
        });
    }

    async fn run(&mut self) {
        // The consensus state (everything else is immutable).
        let mut state = State::new(self.genesis.clone());
        let mut pending_commit_checks: Vec<PendingCommitCheck> = Vec::new();

        // Listen to incoming certificates.
        while let Some(certificate) = self.rx_primary.recv().await {
            debug!("Processing {:?}", certificate);
            let round = certificate.round();
            let certificate_digest = certificate.digest();

            // Add the new certificate to the local storage.
            state.insert(certificate);

            // Emit DAG visualization for extract_final_dag / extract_dag_out (full DAG per round).
            // self.visualize_dag(&state, round);

            let mut cleared = Vec::new();
            pending_commit_checks.retain(|pending| {
                let keep = pending.leader_round > state.last_committed_leader_round;
                if !keep {
                    cleared.push((pending.path, pending.leader_round, pending.support_round));
                }
                keep
            });
            for (path, leader_round, support_round) in cleared {
                debug!(
                    "Clearing pending commit check path={} leader_round={} support_round={} because it is already committed",
                    path.log_label(),
                    leader_round,
                    support_round
                );
            }

            let mut evaluate_pending_indices = Vec::new();
            let candidates = self.pending_commit_checks_for_round(round, &state);
            if let Some(newest_leader_round) =
                candidates.iter().map(|candidate| candidate.leader_round).max()
            {
                let mut retired = Vec::new();
                pending_commit_checks.retain(|pending| {
                    let keep = pending.leader_round >= newest_leader_round;
                    if !keep {
                        retired.push((pending.path, pending.leader_round, pending.support_round));
                    }
                    keep
                });
                for (path, leader_round, support_round) in retired {
                    debug!(
                        "Retiring pending commit check path={} leader_round={} support_round={} because newer leader window {} started at round {}",
                        path.log_label(),
                        leader_round,
                        support_round,
                        newest_leader_round,
                        round
                    );
                }
            }
            for candidate in candidates {
                if let Some((index, pending)) = pending_commit_checks
                    .iter_mut()
                    .enumerate()
                    .find(|(_, pending)| pending.matches(&candidate))
                {
                    // The default wave-start fallback must still re-evaluate the same
                    // (path, leader_round, support_round) tuple even if an earlier fast path
                    // already created it. In that case it clears the candidate gate.
                    pending.candidate_gate_enabled &= candidate.candidate_gate_enabled;
                    evaluate_pending_indices.push(index);
                    continue;
                }
                debug!(
                    "Activating pending commit check path={} leader_round={} support_round={} at round {}",
                    candidate.path.log_label(),
                    candidate.leader_round,
                    candidate.support_round,
                    round
                );
                pending_commit_checks.push(candidate);
                evaluate_pending_indices.push(pending_commit_checks.len() - 1);
            }

            for (index, pending) in pending_commit_checks.iter_mut().enumerate() {
                let should_evaluate_pending = evaluate_pending_indices.contains(&index);
                if self.committee.enable_commit_recheck
                    && !should_evaluate_pending
                    && round == pending.support_round
                    && !pending
                        .seen_support_certificate_digests
                        .contains(&certificate_digest)
                {
                    debug!(
                        "Rechecking pending commit path={} leader_round={} support_round={} due to late support certificate at round {}",
                        pending.path.log_label(),
                        pending.leader_round,
                        pending.support_round,
                        round
                    );
                    evaluate_pending_indices.push(index);
                }
            }

            evaluate_pending_indices.sort_unstable();
            evaluate_pending_indices.dedup();
            evaluate_pending_indices.sort_by_key(|index| {
                let pending = &pending_commit_checks[*index];
                (pending.leader_round, pending.path.sort_key(), pending.support_round)
            });

            for index in evaluate_pending_indices {
                if index >= pending_commit_checks.len() {
                    continue;
                }
                let committed = {
                    let pending = &mut pending_commit_checks[index];
                    self.evaluate_pending_commit_check(&mut state, round, pending)
                        .await
                };
                if committed {
                    pending_commit_checks
                        .retain(|pending| pending.leader_round > state.last_committed_leader_round);
                    break;
                }
            }
        }
    }

    /// Map authority public key to node id (0..n-1), same as visualize_dag / extract_dag_out.
    fn author_to_node_id(&self, author: PublicKey) -> usize {
        self.author_to_node.get(&author).copied().unwrap_or(999)
    }

    fn support_certificate_digests(state: &State, support_round: Round) -> HashSet<Digest> {
        state
            .dag
            .get(&support_round)
            .map(|support_round_map| {
                support_round_map
                    .values()
                    .map(|(digest, _)| digest.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn activation_candidate_threshold(&self, path: CommitCheckPath) -> usize {
        match path {
            CommitCheckPath::FastCoin => self.committee.fast_coin_candidate_threshold,
            CommitCheckPath::Solid => self.committee.solid_candidate_threshold,
        }
    }

    fn support_round_total_stake(&self, state: &State, support_round: Round) -> Stake {
        state
            .dag
            .get(&support_round)
            .map(|support_round_map| {
                support_round_map
                    .values()
                    .map(|(_, certificate)| self.committee.stake(&certificate.origin()))
                    .sum()
            })
            .unwrap_or_default()
    }

    fn supported_candidate_count(
        &self,
        path: CommitCheckPath,
        leader_round: Round,
        support_round: Round,
        state: &State,
    ) -> usize {
        let threshold = self.committee.validity_threshold();
        let Some(leader_round_map) = state.dag.get(&leader_round) else {
            return 0;
        };
        let Some(support_round_map) = state.dag.get(&support_round) else {
            return 0;
        };

        leader_round_map
            .values()
            .filter(|(leader_digest, leader)| {
                let leader_header_id = leader.header.id.clone();
                let support_stake: Stake = support_round_map
                    .values()
                    .filter_map(|(_, certificate)| {
                        let (supports, _, _) = self.certificate_supports_leader(
                            path,
                            certificate,
                            &leader_header_id,
                            leader_digest,
                            leader,
                            state,
                        );
                        supports.then(|| self.committee.stake(&certificate.origin()))
                    })
                    .sum();
                support_stake >= threshold
            })
            .count()
    }

    fn build_pending_commit_check(
        &self,
        path: CommitCheckPath,
        leader_round: Round,
        support_round: Round,
        candidate_gate_enabled: bool,
        state: &State,
    ) -> Option<PendingCommitCheck> {
        if leader_round <= state.last_committed_leader_round {
            return None;
        }

        Some(PendingCommitCheck {
            path,
            leader_round,
            support_round,
            candidate_gate_enabled,
            seen_support_certificate_digests: Self::support_certificate_digests(
                state,
                support_round,
            ),
        })
    }

    fn solid_pending_commit_check_on_solid_step(
        &self,
        round: Round,
        state: &State,
    ) -> Option<PendingCommitCheck> {
        let step_length = self.committee.solid_step_length();
        if round <= step_length + 1 {
            return None;
        }

        let support_round = round - 1;
        if !self.committee.is_solid_step(support_round) {
            return None;
        }

        let leader_round = support_round - step_length;
        if leader_round != 1 && !self.committee.is_solid_wave(leader_round) {
            return None;
        }
        self.build_pending_commit_check(
            CommitCheckPath::Solid,
            leader_round,
            support_round,
            true,
            state,
        )
    }

    /// Default solid-path fallback: activate on the **first certificate** whose `round` is the
    /// first round of a new solid wave after genesis — for σ=κ=2 that is the **first round-5
    /// vertex**, then first vertex of round 9, 13, … Unlike the optional earlier paths, this
    /// fallback does not wait for any candidate-threshold gate.
    fn solid_pending_commit_check_on_wave_start(
        &self,
        round: Round,
        state: &State,
    ) -> Option<PendingCommitCheck> {
        if self.committee.sigma == 1 && self.committee.kappa == 1 {
            return None;
        }

        if !self
            .committee
            .is_first_round_of_second_or_later_solid_wave(round)
        {
            return None;
        }

        let wave = self.committee.solid_wave_length();
        let prev_wave_start = round.saturating_sub(wave);
        let prev_wave_end = round - 1;
        let support_round = self.committee.last_solid_step_round_in_closed_range(
            prev_wave_start,
            prev_wave_end,
        )?;
        let leader_round = prev_wave_start;
        if leader_round < 1 {
            return None;
        }
        if leader_round != 1 && !self.committee.is_solid_wave(leader_round) {
            return None;
        }
        self.build_pending_commit_check(
            CommitCheckPath::Solid,
            leader_round,
            support_round,
            false,
            state,
        )
    }

    fn sigma_one_immediate_pending_commit_check_for_round(
        &self,
        round: Round,
        state: &State,
    ) -> Option<PendingCommitCheck> {
        if self.committee.sigma != 1 || self.committee.kappa != 1 || round <= 1 {
            return None;
        }

        // Restore the legacy sigma=1 behavior: trigger exactly once when the
        // support round first reaches `coverage`, then rely on the normal
        // recheck path (if enabled) for any later support certificates.
        if self.support_round_total_stake(state, round) != self.committee.coverage as Stake {
            return None;
        }

        let leader_round = round - 1;
        if leader_round != 1 && !self.committee.is_solid_wave(leader_round) {
            return None;
        }

        self.build_pending_commit_check(
            CommitCheckPath::Solid,
            leader_round,
            round,
            false,
            state,
        )
    }

    fn solid_pending_commit_checks_for_round(
        &self,
        round: Round,
        state: &State,
    ) -> Vec<PendingCommitCheck> {
        let mut candidates = Vec::new();
        if self.committee.solid_commit_trigger_on_solid_step {
            if let Some(candidate) = self.solid_pending_commit_check_on_solid_step(round, state) {
                candidates.push(candidate);
            }
        }
        if let Some(candidate) = self.solid_pending_commit_check_on_wave_start(round, state) {
            candidates.push(candidate);
        }
        candidates
    }

    fn solid_pending_commit_check_for_round(
        &self,
        round: Round,
        state: &State,
    ) -> Option<PendingCommitCheck> {
        self.solid_pending_commit_checks_for_round(round, state)
            .into_iter()
            .reduce(|mut merged, candidate| {
                merged.candidate_gate_enabled &=
                    candidate.candidate_gate_enabled;
                merged
            })
    }

    fn fast_coin_pending_commit_check_for_round(
        &self,
        round: Round,
        state: &State,
    ) -> Option<PendingCommitCheck> {
        if !self.committee.enable_fast_coin {
            return None;
        }

        let step_length = self.committee.solid_step_length();
        if step_length <= 1 || round <= step_length {
            return None;
        }

        if !self.committee.is_solid_step(round) {
            return None;
        }

        let support_round = round - 1;
        let leader_round = support_round - step_length + 1;
        if leader_round != 1 && !self.committee.is_solid_wave(leader_round) {
            return None;
        }

        self.build_pending_commit_check(
            CommitCheckPath::FastCoin,
            leader_round,
            support_round,
            true,
            state,
        )
    }

    fn pending_commit_checks_for_round(
        &self,
        round: Round,
        state: &State,
    ) -> Vec<PendingCommitCheck> {
        let mut candidates = Vec::new();
        if let Some(candidate) = self.sigma_one_immediate_pending_commit_check_for_round(round, state)
        {
            candidates.push(candidate);
        }
        if let Some(candidate) = self.fast_coin_pending_commit_check_for_round(round, state) {
            candidates.push(candidate);
        }
        for candidate in self.solid_pending_commit_checks_for_round(round, state) {
            candidates.push(candidate);
        }
        candidates
    }

    fn certificate_supports_leader(
        &self,
        path: CommitCheckPath,
        certificate: &Certificate,
        leader_header_id: &Digest,
        leader_digest: &Digest,
        leader: &Certificate,
        state: &State,
    ) -> (bool, bool, bool) {
        let summary_vertices = match path {
            CommitCheckPath::Solid => &certificate.header.solid_wave_vertices,
            CommitCheckPath::FastCoin => &certificate.header.solid_step_vertices,
        };
        let summary_support =
            summary_vertices.contains(leader_header_id) || summary_vertices.contains(leader_digest);
        let parent_path_support =
            matches!(path, CommitCheckPath::FastCoin) && self.linked(certificate, leader, state);
        (summary_support || parent_path_support, summary_support, parent_path_support)
    }

    async fn evaluate_pending_commit_check(
        &mut self,
        state: &mut State,
        trigger_round: Round,
        pending: &mut PendingCommitCheck,
    ) -> bool {
        let path = pending.path;
        let leader_round = pending.leader_round;
        let support_round = pending.support_round;

        let candidate_threshold = self.activation_candidate_threshold(path);
        if pending.candidate_gate_enabled && candidate_threshold > 0 {
            let support_round_stake = self.support_round_total_stake(state, support_round);
            let validity_threshold = self.committee.validity_threshold();
            let supported_candidates =
                self.supported_candidate_count(path, leader_round, support_round, state);
            if support_round_stake < validity_threshold || supported_candidates < candidate_threshold
            {
                debug!(
                    "Commit activation gate blocked path={} leader_round={} support_round={} trigger_round={} support_stake={} validity_threshold={} supported_candidates={} candidate_threshold={}",
                    path.log_label(),
                    leader_round,
                    support_round,
                    trigger_round,
                    support_round_stake,
                    validity_threshold,
                    supported_candidates,
                    candidate_threshold,
                );
                pending.seen_support_certificate_digests =
                    Self::support_certificate_digests(state, support_round);
                return false;
            }
        }

        let (leader_digest, leader) = match self.leader(leader_round, &state.dag) {
            Some((digest, cert)) => (digest.clone(), cert.clone()),
            None => {
                debug!(
                    "No leader in DAG for path={} leader_round {} (support_round={}, trigger_round={})",
                    path.log_label(),
                    leader_round,
                    support_round,
                    trigger_round
                );
                pending.seen_support_certificate_digests =
                    Self::support_certificate_digests(state, support_round);
                return false;
            }
        };

        let leader_header_id = leader.header.id.clone();
        if log_enabled!(log::Level::Debug) {
            let header_pos = self.find_certificate_in_dag(state, &leader_header_id);
            let cert_pos = self.find_certificate_in_dag(state, &leader_digest);

            debug!(
                "Commit validity check: path={}, trigger_round={}, leader_round={}, support_round={}. \
leader_header_id={:?} -> {:?} (node_id={}); \
leader_digest(cert)= {:?} -> {:?} (node_id={})",
                path.log_label(),
                trigger_round,
                leader_round,
                support_round,
                leader_header_id,
                header_pos.as_ref().map(|(rd, _)| rd),
                header_pos
                    .map(|(_, a)| self.author_to_node_id(a))
                    .unwrap_or(999),
                leader_digest,
                cert_pos.as_ref().map(|(rd, _)| rd),
                cert_pos
                    .map(|(_, a)| self.author_to_node_id(a))
                    .unwrap_or(999),
            );
        }

        let support_round_map = state.dag.get(&support_round);
        let debug_logging = log_enabled!(log::Level::Debug);
        let mut support_nodes = Vec::new();
        let mut support_entries = if debug_logging {
            Some(Vec::with_capacity(
                support_round_map.map_or(0, |entries| entries.len()),
            ))
        } else {
            None
        };
        let mut stake = 0;
        if let Some(support_round_map) = support_round_map {
            for (_, certificate) in support_round_map.values() {
                let (supports, summary_support, parent_path_support) = self
                    .certificate_supports_leader(
                        path,
                        certificate,
                        &leader_header_id,
                        &leader_digest,
                        &leader,
                        state,
                    );
                let node_id = self.author_to_node_id(certificate.origin());

                if supports {
                    support_nodes.push(node_id);
                    stake += self.committee.stake(&certificate.origin());
                }

                if let Some(entries) = support_entries.as_mut() {
                    let detail = match path {
                        CommitCheckPath::Solid => format!(
                            "[{},{}]:support={} wave=[{}] merged=[{}]",
                            certificate.round(),
                            node_id,
                            supports,
                            self.render_digest_set(state, &certificate.header.solid_wave_vertices),
                            self.render_digest_set(
                                state,
                                &certificate.header.solid_wave_vertices_merged
                            ),
                        ),
                        CommitCheckPath::FastCoin => format!(
                            "[{},{}]:support={} step_hit={} parent_path={} step=[{}] wave=[{}]",
                            certificate.round(),
                            node_id,
                            supports,
                            summary_support,
                            parent_path_support,
                            self.render_digest_set(state, &certificate.header.solid_step_vertices),
                            self.render_digest_set(state, &certificate.header.solid_wave_vertices),
                        ),
                    };
                    entries.push(detail);
                }
            }
        }

        support_nodes.sort_unstable();
        let threshold = self.committee.validity_threshold();
        let leader_node = self.author_to_node_id(leader.origin());
        pending.seen_support_certificate_digests =
            Self::support_certificate_digests(state, support_round);
        if stake < threshold {
            debug!(
                "DAG_COMMIT_CHECK path={} leader_round={} leader_node={} support_round={} support_basis={} trigger_round={} stake={} threshold={} result=insufficient_stake support_set={:?}",
                path.log_label(),
                leader_round,
                leader_node,
                support_round,
                path.support_basis_label(),
                trigger_round,
                stake,
                threshold,
                support_nodes
            );
            if log_enabled!(log::Level::Debug) && stake == 0 {
                debug!(
                    "Validity stake=0 detail: leader_round={}, support_round={}, leader_header_id={:?}, leader_digest(cert)={:?}",
                    leader_round, support_round, leader_header_id, leader_digest
                );

                if let Some(round_map) = state.dag.get(&support_round) {
                    let mut certs: Vec<_> = round_map.values().collect();
                    certs.sort_by_key(|(_, cert)| self.author_to_node_id(cert.origin()));

                    for (cert_digest, cert) in certs {
                        let origin = cert.origin();
                        let node_id = self.author_to_node_id(origin);

                        let vertices = match path {
                            CommitCheckPath::Solid => &cert.header.solid_wave_vertices,
                            CommitCheckPath::FastCoin => &cert.header.solid_step_vertices,
                        };
                        let contains_leader_header = vertices.contains(&leader_header_id);
                        let contains_leader_digest = vertices.contains(&leader_digest);
                        let parent_path_support =
                            matches!(path, CommitCheckPath::FastCoin) && self.linked(cert, &leader, state);

                        let mut resolved: Vec<String> = Vec::with_capacity(vertices.len());
                        for d in vertices.iter() {
                            if let Some((rd, a)) = self.find_certificate_in_dag(state, d) {
                                let nid = self.author_to_node_id(a);
                                resolved.push(format!("[{},{}]", rd, nid));
                            } else {
                                resolved.push("[?,?]".to_string());
                            }
                        }
                        resolved.sort();

                        debug!(
                            "support_round cert: node={} cert_round={} cert_digest={:?} basis={} base_len={} contains(leader_header_id)={} contains(leader_digest)={} parent_path={} vertices={}",
                            node_id,
                            cert.round(),
                            cert_digest,
                            path.support_basis_label(),
                            vertices.len(),
                            contains_leader_header,
                            contains_leader_digest,
                            parent_path_support,
                            resolved.join(", ")
                        );
                    }
                } else {
                    debug!(
                        "Validity stake=0 detail: support_round {} missing from local DAG",
                        support_round
                    );
                }
            }
            debug!(
                "Current stake is {}. Leader {:?} does not have enough support",
                stake, leader
            );
            if let Some(entries) = support_entries {
                debug!(
                    "DAG_COMMIT_SUPPORT path={} leader_round={} support_round={} trigger_round={} detail={}",
                    path.log_label(),
                    leader_round,
                    support_round,
                    trigger_round,
                    entries.join(" | ")
                );
            }
            return false;
        }

        debug!(
            "DAG_COMMIT_CHECK path={} leader_round={} leader_node={} support_round={} support_basis={} trigger_round={} stake={} threshold={} result=committed support_set={:?}",
            path.log_label(),
            leader_round,
            leader_node,
            support_round,
            path.support_basis_label(),
            trigger_round,
            stake,
            threshold,
            support_nodes
        );
        if let Some(entries) = support_entries {
            debug!(
                "DAG_COMMIT_SUPPORT path={} leader_round={} support_round={} trigger_round={} detail={}",
                path.log_label(),
                leader_round,
                support_round,
                trigger_round,
                entries.join(" | ")
            );
        }

        debug!("Leader {:?} has enough support", leader);
        let mut sequence = Vec::new();
        for leader in self.order_leaders(&leader, state).iter().rev() {
            for x in self.order_dag(leader, state) {
                state.update(&x, self.gc_depth);
                sequence.push(x);
            }
        }
        state.update_last_committed_leader(leader_round);

        if log_enabled!(log::Level::Debug) {
            for (name, round) in &state.last_committed {
                debug!("Latest commit of {}: Round {}", name, round);
            }
        }

        for certificate in sequence {
            let node_id = self.author_to_node_id(certificate.origin());
            debug!(
                "DAG_COMMITTED round={} node={} digest={:?}",
                certificate.round(),
                node_id,
                certificate.digest()
            );
            #[cfg(not(feature = "benchmark"))]
            info!("Committed {}", certificate.header);

            #[cfg(feature = "benchmark")]
            for digest in certificate.header.payload.keys() {
                info!("Committed {} -> {:?}", certificate.header, digest);
            }

            self.tx_primary
                .send(certificate.clone())
                .await
                .expect("Failed to send certificate to primary");

            if let Err(e) = self.tx_output.send(certificate).await {
                warn!("Failed to output certificate: {}", e);
            }
        }

        true
    }

    /// Returns the certificate (and the certificate's digest) originated by the leader of the
    /// specified round (if any).
    fn leader<'a>(&self, round: Round, dag: &'a Dag) -> Option<&'a (Digest, Certificate)> {
        // TODO: We should elect the leader of round r-2 using the common coin revealed at round r.
        // At this stage, we are guaranteed to have 2f+1 certificates from round r (which is enough to
        // compute the coin). We currently just use round-robin.
        #[cfg(test)]
        let coin = 0;
        #[cfg(not(test))]
        let coin = round;

        // Elect the leader.
        let leader = self.authorities[coin as usize % self.authorities.len()];

        // Return its certificate and the certificate's digest.
        dag.get(&round).map(|x| x.get(&leader)).flatten()
    }

    /// Order leader certificates to commit, stepping backwards across solid-wave
    /// boundary rounds (1, 1+wave, 1+2*wave, ...).
    fn order_leaders(&self, leader: &Certificate, state: &State) -> Vec<Certificate> {
        let wave = self.committee.solid_wave_length();
        if wave == 0 {
            return vec![leader.clone()];
        }
        let start = state
            .last_committed_leader_round
            .saturating_add(wave);
        let end_round = leader.round();
        let mut to_commit = vec![leader.clone()];
        let mut cur = leader;
        if end_round <= start {
            return to_commit;
        }

        let mut r = end_round.saturating_sub(wave);
        loop {
            let (_, prev_leader) = match self.leader(r, &state.dag) {
                Some(x) => x,
                None => {
                    if r < start + wave {
                        break;
                    }
                    r = r.saturating_sub(wave);
                    continue;
                }
            };
            if self.linked(cur, prev_leader, state) {
                to_commit.push(prev_leader.clone());
                cur = prev_leader;
            }
            if r < start + wave {
                break;
            }
            r = r.saturating_sub(wave);
        }
        debug!(
            "order_leaders: chain_len={} tip_round={} last_committed_leader_round={} gap_rounds={} step={}",
            to_commit.len(),
            end_round,
            state.last_committed_leader_round,
            end_round.saturating_sub(state.last_committed_leader_round),
            wave
        );
        to_commit
    }

    /// Find a parent certificate by digest in any ancestor round (< child_round).
    fn find_parent_certificate<'a>(
        &self,
        state: &'a State,
        child_round: Round,
        parent_digest: &Digest,
    ) -> Option<&'a (Digest, Certificate)> {
        if child_round <= 1 {
            return None;
        }
        state
            .find_certificate(parent_digest)
            .filter(|(_, certificate)| certificate.round() < child_round)
    }

    /// Checks if there is a path between two leaders.
    /// Unlike the original implementation, this traversal follows weak edges too.
    fn linked(&self, leader: &Certificate, prev_leader: &Certificate, state: &State) -> bool {
        let target = prev_leader.digest();
        let mut stack = vec![leader];
        let mut visited = HashSet::new();

        while let Some(current) = stack.pop() {
            let current_digest = current.digest();
            if !visited.insert(current_digest.clone()) {
                continue;
            }
            if current_digest == target {
                return true;
            }

            for parent in &current.header.parents {
                if let Some((_, parent_cert)) =
                    self.find_parent_certificate(state, current.round(), parent)
                {
                    stack.push(parent_cert);
                }
            }
        }
        false
    }

    /// Flatten the dag referenced by the input certificate. This is a classic depth-first search (pre-order):
    /// https://en.wikipedia.org/wiki/Tree_traversal#Pre-order
    fn order_dag(&self, leader: &Certificate, state: &State) -> Vec<Certificate> {
        debug!("Processing sub-dag of {:?}", leader);
        let mut ordered = Vec::new();
        let mut already_ordered: HashSet<Digest> = HashSet::new();

        let mut buffer = vec![leader];
        while let Some(x) = buffer.pop() {
            debug!("Sequencing {:?}", x);
            ordered.push(x.clone());
            for parent in &x.header.parents {
                let (digest, certificate) =
                    match self.find_parent_certificate(state, x.round(), parent) {
                        Some(x) => x,
                        None => continue, // Parent already GC'ed or not in local DAG.
                    };

                // We skip the certificate if we (1) already processed it or (2) we reached a round that we already
                // committed for this authority.
                let mut skip = already_ordered.contains(digest);
                skip |= state
                    .last_committed
                    .get(&certificate.origin())
                    .map_or_else(|| false, |r| r == &certificate.round());
                if !skip {
                    buffer.push(certificate);
                    already_ordered.insert(digest.clone());
                }
            }
        }

        // Ensure we do not commit garbage collected certificates.
        ordered.retain(|x| x.round() + self.gc_depth >= state.last_committed_certificate_round);

        // Ordering the output by round is not really necessary but it makes the commit sequence prettier.
        ordered.sort_by_key(|x| x.round());
        ordered
    }

    fn visualize_dag(&self, state: &State, current_round: Round) {
        // from current_round to round 1, reverse
        for round in (1..=current_round).rev() {
            if state.dag.contains_key(&round) {
                let round_certs = state.dag.get(&round).unwrap();
                let mut round_output = format!("Round {}:", round);
                let mut vertices = Vec::new();

                let mut sorted_certs: Vec<_> = round_certs.iter().collect();
                sorted_certs.sort_by_key(|(author, _)| *author);

                for (author, (_cert_digest, certificate)) in sorted_certs {
                    let node_id = self.author_to_node.get(author).unwrap_or(&999);
                    let vertex_name = format!("Vertex{}", node_id);

                    // find the parent nodes
                    let mut parents = Vec::new();
                    let mut weak_parents = Vec::new();
                    for parent_digest in &certificate.header.parents {
                        // find the parent certificate in the dag
                        if let Some((parent_round, parent_author)) =
                            self.find_certificate_in_dag(state, parent_digest)
                        {
                            let parent_node_id =
                                self.author_to_node.get(&parent_author).unwrap_or(&999);
                            let is_weak = parent_round + 1 != round;
                            if is_weak {
                                let weak_entry = format!("[w{},{}]", parent_round, parent_node_id);
                                parents.push(weak_entry.clone());
                                weak_parents.push(weak_entry);
                            } else {
                                parents.push(format!("[{},{}]", parent_round, parent_node_id));
                            }
                        } else {
                            // if the block is genesis, do not need to output
                            if round != 1 {
                                parents.push("[?,?]".to_string());
                            }
                        }
                    }

                    let parent_str = if parents.is_empty() {
                        "[]".to_string()
                    } else {
                        format!("[{}]", parents.join(", "))
                    };

                    // Resolve each solid_wave_vertex digest to [round, node_id] for explicit display.
                    let mut solid_vertices = Vec::new();
                    for digest in &certificate.header.solid_wave_vertices {
                        if let Some((r, author)) = self.find_certificate_in_dag(state, digest) {
                            let n = self.author_to_node.get(&author).unwrap_or(&999);
                            solid_vertices.push(format!("[{},{}]", r, n));
                        } else {
                            solid_vertices.push("[?,?]".to_string());
                        }
                    }
                    let solid_str = if solid_vertices.is_empty() {
                        "".to_string()
                    } else {
                        format!(" solid=[{}]", solid_vertices.join(", "))
                    };

                    // Resolve each merged solid_wave_vertex digest to [round, node_id].
                    let mut merged_vertices = Vec::new();
                    for digest in &certificate.header.solid_wave_vertices_merged {
                        if let Some((r, author)) = self.find_certificate_in_dag(state, digest) {
                            let n = self.author_to_node.get(&author).unwrap_or(&999);
                            merged_vertices.push(format!("[{},{}]", r, n));
                        } else {
                            merged_vertices.push("[?,?]".to_string());
                        }
                    }
                    let merged_str = if merged_vertices.is_empty() {
                        "".to_string()
                    } else {
                        format!(" merged=[{}]", merged_vertices.join(", "))
                    };

                    let vertex_str = if weak_parents.is_empty() {
                        format!(
                            "({}){} (solid_wave_vertices: {}){}{}",
                            vertex_name,
                            parent_str,
                            certificate.header.solid_wave_vertices.len(),
                            solid_str,
                            merged_str
                        )
                    } else {
                        format!(
                            "({}){} weak=[{}] (solid_wave_vertices: {}){}{}",
                            vertex_name,
                            parent_str,
                            weak_parents.join(", "),
                            certificate.header.solid_wave_vertices.len(),
                            solid_str,
                            merged_str
                        )
                    };
                    vertices.push(vertex_str);
                }

                if !vertices.is_empty() {
                    round_output.push_str(&format!(" {} ", vertices.join(" --- ")));
                    debug!("{}", round_output);
                }
            }
        }
    }

    fn find_certificate_in_dag(
        &self,
        state: &State,
        digest: &Digest,
    ) -> Option<(Round, PublicKey)> {
        state.find_digest(digest)
    }

    fn render_digest_set(&self, state: &State, digests: &HashSet<Digest>) -> String {
        let mut resolved = Vec::with_capacity(digests.len());
        for digest in digests {
            if let Some((round, author)) = self.find_certificate_in_dag(state, digest) {
                resolved.push(format!("[{},{}]", round, self.author_to_node_id(author)));
            } else {
                resolved.push("[?,?]".to_string());
            }
        }
        resolved.sort();
        resolved.join(", ")
    }
}
