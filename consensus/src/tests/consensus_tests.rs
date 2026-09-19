// Copyright(C) Facebook, Inc. and its affiliates.
use super::*;
use config::{Authority, PrimaryAddresses};
use crypto::{generate_keypair, SecretKey};
use primary::Header;
use rand::rngs::StdRng;
use rand::SeedableRng as _;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use tokio::sync::mpsc::channel;

// Fixture
fn keys() -> Vec<(PublicKey, SecretKey)> {
    let mut rng = StdRng::from_seed([0; 32]);
    (0..4).map(|_| generate_keypair(&mut rng)).collect()
}

// Fixture
pub fn mock_committee() -> Committee {
    Committee {
        authorities: keys()
            .iter()
            .map(|(id, _)| {
                (
                    *id,
                    Authority {
                        stake: 1,
                        primary: PrimaryAddresses {
                            primary_to_primary: "0.0.0.0:0".parse().unwrap(),
                            worker_to_primary: "0.0.0.0:0".parse().unwrap(),
                        },
                        workers: HashMap::default(),
                    },
                )
            })
            .collect(),
        sigma: 2,
        kappa: 2,
        reference: 3,
        coverage: 3,
        allow_cross_step_weak_edges: true,
        enable_fast_coin: false,
        enable_commit_recheck: true,
        fast_coin_candidate_threshold: 0,
        solid_candidate_threshold: 0,
        solid_commit_trigger_on_solid_step: true,
        attack_enabled: false,
        attack_start_secs: 0,
        attack_duration_secs: 0,
        attack_group_size: 0,
        attack_limit_headers: false,
        attack_limit_certificates: true,
    }
}

// Fixture
fn mock_certificate(
    origin: PublicKey,
    round: Round,
    parents: BTreeSet<Digest>,
) -> (Digest, Certificate) {
    let certificate = Certificate {
        header: Header {
            author: origin,
            round,
            parents,
            ..Header::default()
        },
        ..Certificate::default()
    };
    (certificate.digest(), certificate)
}

fn mock_certificate_with_solid_wave(
    origin: PublicKey,
    round: Round,
    parents: BTreeSet<Digest>,
    solid_wave_vertices: HashSet<Digest>,
) -> (Digest, Certificate) {
    let certificate = Certificate {
        header: Header {
            author: origin,
            round,
            parents,
            solid_wave_vertices,
            ..Header::default()
        },
        ..Certificate::default()
    };
    (certificate.digest(), certificate)
}

fn mock_certificate_with_solid_step(
    origin: PublicKey,
    round: Round,
    parents: BTreeSet<Digest>,
    solid_step_vertices: HashSet<Digest>,
) -> (Digest, Certificate) {
    let certificate = Certificate {
        header: Header {
            author: origin,
            round,
            parents,
            solid_step_vertices,
            ..Header::default()
        },
        ..Certificate::default()
    };
    (certificate.digest(), certificate)
}

// Creates one certificate per authority starting and finishing at the specified rounds (inclusive).
// Outputs a VecDeque of certificates (the certificate with higher round is on the front) and a set
// of digests to be used as parents for the certificates of the next round.
fn make_certificates(
    start: Round,
    stop: Round,
    initial_parents: &BTreeSet<Digest>,
    keys: &[PublicKey],
) -> (VecDeque<Certificate>, BTreeSet<Digest>) {
    let mut certificates = VecDeque::new();
    let mut parents = initial_parents.iter().cloned().collect::<BTreeSet<_>>();
    let mut next_parents = BTreeSet::new();

    for round in start..=stop {
        next_parents.clear();
        for name in keys {
            let (digest, certificate) = mock_certificate(*name, round, parents.clone());
            certificates.push_back(certificate);
            next_parents.insert(digest);
        }
        parents = next_parents.clone();
    }
    (certificates, next_parents)
}

// Run for 4 dag rounds in ideal conditions (all nodes reference all other nodes). We should commit
// the leader of round 2.
#[tokio::test]
async fn commit_one() {
    // Make certificates for rounds 1 to 4.
    let keys: Vec<_> = keys().into_iter().map(|(x, _)| x).collect();
    let genesis = Certificate::genesis(&mock_committee())
        .iter()
        .map(|x| x.digest())
        .collect::<BTreeSet<_>>();
    let (mut certificates, next_parents) = make_certificates(1, 4, &genesis, &keys);

    // Make one certificate with round 5 to trigger the commits.
    let (_, certificate) = mock_certificate(keys[0], 5, next_parents);
    certificates.push_back(certificate);

    // Spawn the consensus engine and sink the primary channel.
    let (tx_waiter, rx_waiter) = channel(1);
    let (tx_primary, mut rx_primary) = channel(1);
    let (tx_output, mut rx_output) = channel(1);
    Consensus::spawn(
        mock_committee(),
        /* gc_depth */ 50,
        rx_waiter,
        tx_primary,
        tx_output,
    );
    tokio::spawn(async move { while rx_primary.recv().await.is_some() {} });

    // Feed all certificates to the consensus. Only the last certificate should trigger
    // commits, so the task should not block.
    while let Some(certificate) = certificates.pop_front() {
        tx_waiter.send(certificate).await.unwrap();
    }

    // Ensure the first 4 ordered certificates are from round 1 (they are the parents of the committed
    // leader); then the leader's certificate should be committed.
    for _ in 1..=4 {
        let certificate = rx_output.recv().await.unwrap();
        assert_eq!(certificate.round(), 1);
    }
    let certificate = rx_output.recv().await.unwrap();
    assert_eq!(certificate.round(), 2);
}

// Run for 8 dag rounds with one dead node node (that is not a leader). We should commit the leaders of
// rounds 2, 4, and 6.
#[tokio::test]
async fn dead_node() {
    // Make the certificates.
    let mut keys: Vec<_> = keys().into_iter().map(|(x, _)| x).collect();
    keys.sort(); // Ensure we don't remove one of the leaders.
    let _ = keys.pop().unwrap();

    let genesis = Certificate::genesis(&mock_committee())
        .iter()
        .map(|x| x.digest())
        .collect::<BTreeSet<_>>();

    let (mut certificates, _) = make_certificates(1, 9, &genesis, &keys);

    // Spawn the consensus engine and sink the primary channel.
    let (tx_waiter, rx_waiter) = channel(1);
    let (tx_primary, mut rx_primary) = channel(1);
    let (tx_output, mut rx_output) = channel(1);
    Consensus::spawn(
        mock_committee(),
        /* gc_depth */ 50,
        rx_waiter,
        tx_primary,
        tx_output,
    );
    tokio::spawn(async move { while rx_primary.recv().await.is_some() {} });

    // Feed all certificates to the consensus.
    tokio::spawn(async move {
        while let Some(certificate) = certificates.pop_front() {
            tx_waiter.send(certificate).await.unwrap();
        }
    });

    // We should commit 3 leaders (rounds 2, 4, and 6).
    for i in 1..=15 {
        let certificate = rx_output.recv().await.unwrap();
        let expected = ((i - 1) / keys.len() as u64) + 1;
        assert_eq!(certificate.round(), expected);
    }
    let certificate = rx_output.recv().await.unwrap();
    assert_eq!(certificate.round(), 6);
}

// Run for 6 dag rounds. The leaders of round 2 does not have enough support, but the leader of
// round 4 does. The leader of rounds 2 and 4 should thus be committed upon entering round 6.
#[tokio::test]
async fn not_enough_support() {
    let mut keys: Vec<_> = keys().into_iter().map(|(x, _)| x).collect();
    keys.sort();

    let genesis = Certificate::genesis(&mock_committee())
        .iter()
        .map(|x| x.digest())
        .collect::<BTreeSet<_>>();

    let mut certificates = VecDeque::new();

    // Round 1: Fully connected graph.
    let nodes: Vec<_> = keys.iter().cloned().take(3).collect();
    let (out, parents) = make_certificates(1, 1, &genesis, &nodes);
    certificates.extend(out);

    // Round 2: Fully connect graph. But remember the digest of the leader. Note that this
    // round is the only one with 4 certificates.
    let (leader_2_digest, certificate) = mock_certificate(keys[0], 2, parents.clone());
    certificates.push_back(certificate);

    let nodes: Vec<_> = keys.iter().cloned().skip(1).collect();
    let (out, mut parents) = make_certificates(2, 2, &parents, &nodes);
    certificates.extend(out);

    // Round 3: Only node 0 links to the leader of round 2.
    let mut next_parents = BTreeSet::new();

    let name = &keys[1];
    let (digest, certificate) = mock_certificate(*name, 3, parents.clone());
    certificates.push_back(certificate);
    next_parents.insert(digest);

    let name = &keys[2];
    let (digest, certificate) = mock_certificate(*name, 3, parents.clone());
    certificates.push_back(certificate);
    next_parents.insert(digest);

    let name = &keys[0];
    parents.insert(leader_2_digest);
    let (digest, certificate) = mock_certificate(*name, 3, parents.clone());
    certificates.push_back(certificate);
    next_parents.insert(digest);

    parents = next_parents.clone();

    // Rounds 4, 5, and 6: Fully connected graph.
    let nodes: Vec<_> = keys.iter().cloned().take(3).collect();
    let (out, parents) = make_certificates(4, 6, &parents, &nodes);
    certificates.extend(out);

    // Round 7: Send a single certificate to trigger the commits.
    let (_, certificate) = mock_certificate(keys[0], 7, parents);
    certificates.push_back(certificate);

    // Spawn the consensus engine and sink the primary channel.
    let (tx_waiter, rx_waiter) = channel(1);
    let (tx_primary, mut rx_primary) = channel(1);
    let (tx_output, mut rx_output) = channel(1);
    Consensus::spawn(
        mock_committee(),
        /* gc_depth */ 50,
        rx_waiter,
        tx_primary,
        tx_output,
    );
    tokio::spawn(async move { while rx_primary.recv().await.is_some() {} });

    // Feed all certificates to the consensus. Only the last certificate should trigger
    // commits, so the task should not block.
    while let Some(certificate) = certificates.pop_front() {
        tx_waiter.send(certificate).await.unwrap();
    }

    // We should commit 2 leaders (rounds 2 and 4).
    for _ in 1..=3 {
        let certificate = rx_output.recv().await.unwrap();
        assert_eq!(certificate.round(), 1);
    }
    for _ in 1..=4 {
        let certificate = rx_output.recv().await.unwrap();
        assert_eq!(certificate.round(), 2);
    }
    for _ in 1..=3 {
        let certificate = rx_output.recv().await.unwrap();
        assert_eq!(certificate.round(), 3);
    }
    let certificate = rx_output.recv().await.unwrap();
    assert_eq!(certificate.round(), 4);
}

// Run for 6 dag rounds. Node 0 (the leader of round 2) is missing for rounds 1 and 2,
// and reapers from round 3.
#[tokio::test]
async fn missing_leader() {
    let mut keys: Vec<_> = keys().into_iter().map(|(x, _)| x).collect();
    keys.sort();

    let genesis = Certificate::genesis(&mock_committee())
        .iter()
        .map(|x| x.digest())
        .collect::<BTreeSet<_>>();

    let mut certificates = VecDeque::new();

    // Remove the leader for rounds 1 and 2.
    let nodes: Vec<_> = keys.iter().cloned().skip(1).collect();
    let (out, parents) = make_certificates(1, 2, &genesis, &nodes);
    certificates.extend(out);

    // Add back the leader for rounds 3, 4, 5 and 6.
    let (out, parents) = make_certificates(3, 6, &parents, &keys);
    certificates.extend(out);

    // Add a certificate of round 7 to commit the leader of round 4.
    let (_, certificate) = mock_certificate(keys[0], 7, parents.clone());
    certificates.push_back(certificate);

    // Spawn the consensus engine and sink the primary channel.
    let (tx_waiter, rx_waiter) = channel(1);
    let (tx_primary, mut rx_primary) = channel(1);
    let (tx_output, mut rx_output) = channel(1);
    Consensus::spawn(
        mock_committee(),
        /* gc_depth */ 50,
        rx_waiter,
        tx_primary,
        tx_output,
    );
    tokio::spawn(async move { while rx_primary.recv().await.is_some() {} });

    // Feed all certificates to the consensus. We should only commit upon receiving the last
    // certificate, so calls below should not block the task.
    while let Some(certificate) = certificates.pop_front() {
        tx_waiter.send(certificate).await.unwrap();
    }

    // Ensure the commit sequence is as expected.
    for _ in 1..=3 {
        let certificate = rx_output.recv().await.unwrap();
        assert_eq!(certificate.round(), 1);
    }
    for _ in 1..=3 {
        let certificate = rx_output.recv().await.unwrap();
        assert_eq!(certificate.round(), 2);
    }
    for _ in 1..=4 {
        let certificate = rx_output.recv().await.unwrap();
        assert_eq!(certificate.round(), 3);
    }
    let certificate = rx_output.recv().await.unwrap();
    assert_eq!(certificate.round(), 4);
}

#[test]
fn solid_commit_wave_start_skips_solid_step_trigger_round() {
    let committee = Committee {
        solid_commit_trigger_on_solid_step: false,
        ..mock_committee()
    };
    let authorities: Vec<_> = committee.authorities.keys().copied().collect();
    let author_to_node = authorities
        .iter()
        .copied()
        .enumerate()
        .map(|(index, authority)| (authority, index))
        .collect();
    let genesis_certs = Certificate::genesis(&committee);
    let genesis_parents = genesis_certs
        .iter()
        .map(|certificate| certificate.digest())
        .collect::<BTreeSet<_>>();

    let (_, leader_round_1) = mock_certificate(authorities[0], 1, genesis_parents);
    let mut state = State::new(genesis_certs.clone());
    state.insert(leader_round_1);

    let (_tx_waiter, rx_waiter) = channel(1);
    let (tx_primary, _rx_primary) = channel(10);
    let (tx_output, _rx_output) = channel(10);
    let consensus = Consensus {
        committee,
        authorities,
        author_to_node,
        gc_depth: 50,
        rx_primary: rx_waiter,
        tx_primary,
        tx_output,
        genesis: genesis_certs,
    };

    assert!(consensus.solid_pending_commit_check_for_round(4, &state).is_none());
    let pending = consensus
        .solid_pending_commit_check_for_round(5, &state)
        .expect("first wave boundary after genesis should activate r3/r1 solid check");
    assert_eq!(pending.support_round, 3);
    assert_eq!(pending.leader_round, 1);
    assert!(!pending.candidate_gate_enabled);
}

#[test]
fn solid_commit_wave_start_uses_previous_wave_start_for_sigma_one_kappa_three() {
    let committee = Committee {
        sigma: 1,
        kappa: 3,
        reference: 3,
        coverage: 3,
        allow_cross_step_weak_edges: false,
        enable_fast_coin: false,
        enable_commit_recheck: false,
        solid_commit_trigger_on_solid_step: false,
        ..mock_committee()
    };
    let authorities: Vec<_> = committee.authorities.keys().copied().collect();
    let author_to_node = authorities
        .iter()
        .copied()
        .enumerate()
        .map(|(index, authority)| (authority, index))
        .collect();
    let genesis_certs = Certificate::genesis(&committee);
    let genesis_parents = genesis_certs
        .iter()
        .map(|certificate| certificate.digest())
        .collect::<BTreeSet<_>>();

    let (_, leader_round_1) = mock_certificate(authorities[0], 1, genesis_parents);
    let mut state = State::new(genesis_certs.clone());
    state.insert(leader_round_1);

    let (_tx_waiter, rx_waiter) = channel(1);
    let (tx_primary, _rx_primary) = channel(10);
    let (tx_output, _rx_output) = channel(10);
    let consensus = Consensus {
        committee,
        authorities,
        author_to_node,
        gc_depth: 50,
        rx_primary: rx_waiter,
        tx_primary,
        tx_output,
        genesis: genesis_certs,
    };

    assert!(consensus.solid_pending_commit_check_for_round(3, &state).is_none());
    let pending = consensus
        .solid_pending_commit_check_for_round(4, &state)
        .expect("round 4 should activate the default wave-start solid check for kappa=3");
    assert_eq!(pending.support_round, 3);
    assert_eq!(pending.leader_round, 1);
    assert!(!pending.candidate_gate_enabled);
}

#[tokio::test]
async fn sigma_one_commits_immediately_when_round_two_reaches_coverage() {
    let committee = Committee {
        sigma: 1,
        kappa: 1,
        reference: 3,
        coverage: 3,
        allow_cross_step_weak_edges: false,
        enable_fast_coin: false,
        enable_commit_recheck: false,
        solid_commit_trigger_on_solid_step: false,
        ..mock_committee()
    };
    let authorities: Vec<_> = committee.authorities.keys().copied().collect();
    let author_to_node = authorities
        .iter()
        .copied()
        .enumerate()
        .map(|(index, authority)| (authority, index))
        .collect();
    let genesis_certs = Certificate::genesis(&committee);
    let genesis_parents = genesis_certs
        .iter()
        .map(|certificate| certificate.digest())
        .collect::<BTreeSet<_>>();

    let leader_author = authorities[0];
    let supporter_a = authorities[1];
    let supporter_b = authorities[2];
    let supporter_c = authorities[3];

    let (_, mut leader_round_1) = mock_certificate(leader_author, 1, genesis_parents.clone());
    leader_round_1.header.id = leader_round_1.header.digest();
    let leader_header_id = leader_round_1.header.id.clone();

    let mut support_vertices = HashSet::new();
    support_vertices.insert(leader_header_id);

    let (_, support_round_2_a) = mock_certificate_with_solid_wave(
        supporter_a,
        2,
        BTreeSet::new(),
        support_vertices.clone(),
    );
    let (_, support_round_2_b) = mock_certificate_with_solid_wave(
        supporter_b,
        2,
        BTreeSet::new(),
        support_vertices.clone(),
    );
    let (_, support_round_2_c) = mock_certificate_with_solid_wave(
        supporter_c,
        2,
        BTreeSet::new(),
        support_vertices,
    );

    let (_tx_waiter, rx_waiter) = channel(1);
    let (tx_primary, mut rx_primary) = channel(10);
    let (tx_output, mut rx_output) = channel(10);
    let mut consensus = Consensus {
        committee,
        authorities,
        author_to_node,
        gc_depth: 50,
        rx_primary: rx_waiter,
        tx_primary,
        tx_output,
        genesis: genesis_certs.clone(),
    };
    tokio::spawn(async move { while rx_primary.recv().await.is_some() {} });

    let mut state = State::new(genesis_certs);
    state.insert(leader_round_1.clone());
    state.insert(support_round_2_a);
    state.insert(support_round_2_b);

    assert!(
        consensus
            .sigma_one_immediate_pending_commit_check_for_round(2, &state)
            .is_none(),
        "sigma=1 should wait until round 2 reaches coverage before activating commit"
    );

    state.insert(support_round_2_c);
    let mut pending = consensus
        .sigma_one_immediate_pending_commit_check_for_round(2, &state)
        .expect("round 2 should activate the sigma=1 immediate commit check once coverage is met");
    assert_eq!(pending.leader_round, 1);
    assert_eq!(pending.support_round, 2);
    assert!(!pending.candidate_gate_enabled);

    let committed = consensus
        .evaluate_pending_commit_check(&mut state, 2, &mut pending)
        .await;
    assert!(
        committed,
        "sigma=1 should commit immediately on round 2 once coverage support is present"
    );

    let committed_leader = rx_output.recv().await.unwrap();
    assert_eq!(committed_leader.round(), 1);
    assert_eq!(committed_leader.origin(), leader_author);
}

#[tokio::test]
async fn sigma_one_without_recheck_does_not_commit_after_late_support() {
    let committee = Committee {
        sigma: 1,
        kappa: 1,
        reference: 3,
        coverage: 3,
        allow_cross_step_weak_edges: false,
        enable_fast_coin: false,
        enable_commit_recheck: false,
        solid_commit_trigger_on_solid_step: false,
        ..mock_committee()
    };
    let authorities: Vec<_> = committee.authorities.keys().copied().collect();
    let author_to_node = authorities
        .iter()
        .copied()
        .enumerate()
        .map(|(index, authority)| (authority, index))
        .collect();
    let genesis_certs = Certificate::genesis(&committee);
    let genesis_parents = genesis_certs
        .iter()
        .map(|certificate| certificate.digest())
        .collect::<BTreeSet<_>>();

    let leader_author = authorities[0];
    let supporter_a = authorities[1];
    let supporter_b = authorities[2];
    let supporter_c = authorities[3];

    let (_, mut leader_round_1) = mock_certificate(leader_author, 1, genesis_parents.clone());
    leader_round_1.header.id = leader_round_1.header.digest();
    let leader_header_id = leader_round_1.header.id.clone();

    let mut support_vertices = HashSet::new();
    support_vertices.insert(leader_header_id);

    let (_, support_round_2_a) = mock_certificate_with_solid_wave(
        supporter_a,
        2,
        BTreeSet::new(),
        HashSet::new(),
    );
    let (_, support_round_2_b) = mock_certificate_with_solid_wave(
        supporter_b,
        2,
        BTreeSet::new(),
        HashSet::new(),
    );
    let (_, support_round_2_c) = mock_certificate_with_solid_wave(
        supporter_c,
        2,
        BTreeSet::new(),
        support_vertices,
    );

    let (_tx_waiter, rx_waiter) = channel(1);
    let (tx_primary, mut rx_primary) = channel(10);
    let (tx_output, mut rx_output) = channel(10);
    let mut consensus = Consensus {
        committee,
        authorities,
        author_to_node,
        gc_depth: 50,
        rx_primary: rx_waiter,
        tx_primary,
        tx_output,
        genesis: genesis_certs.clone(),
    };
    tokio::spawn(async move { while rx_primary.recv().await.is_some() {} });

    let mut state = State::new(genesis_certs);
    state.insert(leader_round_1.clone());
    state.insert(support_round_2_a);
    state.insert(support_round_2_b);

    assert!(
        consensus
            .sigma_one_immediate_pending_commit_check_for_round(2, &state)
            .is_none(),
        "sigma=1 should not activate before coverage is first reached"
    );
    assert!(
        consensus.solid_pending_commit_check_for_round(3, &state).is_none(),
        "sigma=1 should not fall back to a wave-start commit check on round 3"
    );

    state.insert(support_round_2_c);
    let mut pending = consensus
        .sigma_one_immediate_pending_commit_check_for_round(2, &state)
        .expect("reaching coverage should still activate exactly one immediate check");
    let committed = consensus
        .evaluate_pending_commit_check(&mut state, 2, &mut pending)
        .await;
    assert!(
        !committed,
        "without enough f+1 support at the first activation, sigma=1 should not commit"
    );

    assert!(
        consensus.solid_pending_commit_check_for_round(3, &state).is_none(),
        "late round-2 support should not be retried when recheck is disabled"
    );
    let no_commit = tokio::time::timeout(std::time::Duration::from_millis(200), rx_output.recv())
        .await;
    assert!(
        no_commit.is_err(),
        "sigma=1 with recheck disabled should not commit after the initial round-2 check"
    );
}

#[tokio::test]
async fn late_support_certificate_rechecks_pending_commit() {
    let _ = env_logger::builder()
        .is_test(true)
        .filter_level(log::LevelFilter::Info)
        .try_init();

    let committee = mock_committee();
    let authorities: Vec<_> = committee.authorities.keys().copied().collect();
    let author_to_node = authorities
        .iter()
        .copied()
        .enumerate()
        .map(|(index, authority)| (authority, index))
        .collect();
    let genesis_certs = Certificate::genesis(&committee);
    let genesis_parents = genesis_certs
        .iter()
        .map(|certificate| certificate.digest())
        .collect::<BTreeSet<_>>();

    let leader_author = authorities[0];
    let supporter_a = authorities[1];
    let supporter_b = authorities[2];

    let (_, leader_round_1) = mock_certificate(leader_author, 1, genesis_parents.clone());
    let leader_header_id = leader_round_1.header.id.clone();

    let mut support_vertices = HashSet::new();
    support_vertices.insert(leader_header_id.clone());

    let (_, support_round_3_a) = mock_certificate_with_solid_wave(
        supporter_a,
        3,
        BTreeSet::new(),
        support_vertices.clone(),
    );
    let (_, activation_round_4) =
        mock_certificate(authorities[3], 4, BTreeSet::from([leader_round_1.digest()]));
    let (_, support_round_3_b) = mock_certificate_with_solid_wave(
        supporter_b,
        3,
        BTreeSet::new(),
        support_vertices,
    );

    let (_tx_waiter, rx_waiter) = channel(1);
    let (tx_primary, mut rx_primary) = channel(10);
    let (tx_output, mut rx_output) = channel(10);
    let mut consensus = Consensus {
        committee: committee.clone(),
        authorities,
        author_to_node,
        gc_depth: 50,
        rx_primary: rx_waiter,
        tx_primary,
        tx_output,
        genesis: genesis_certs.clone(),
    };
    tokio::spawn(async move { while rx_primary.recv().await.is_some() {} });

    let mut state = State::new(genesis_certs);
    state.insert(leader_round_1.clone());
    state.insert(support_round_3_a.clone());
    state.insert(activation_round_4.clone());

    let mut pending = consensus
        .solid_pending_commit_check_for_round(4, &state)
        .expect("round 4 should activate a pending commit check");

    let committed = consensus
        .evaluate_pending_commit_check(&mut state, 4, &mut pending)
        .await;
    assert!(!committed, "one support certificate should not be enough to commit");

    let late_support_digest = support_round_3_b.digest();
    assert!(
        !pending
            .seen_support_certificate_digests
            .contains(&late_support_digest),
        "the late support certificate should not be marked as seen before insertion"
    );

    state.insert(support_round_3_b);
    let committed = consensus
        .evaluate_pending_commit_check(&mut state, 3, &mut pending)
        .await;
    assert!(committed, "a late support certificate should re-trigger and complete the commit");

    let committed_leader = rx_output.recv().await.unwrap();
    assert_eq!(committed_leader.round(), 1);
    assert_eq!(committed_leader.origin(), leader_author);
}

#[tokio::test]
async fn late_support_certificate_does_not_recheck_when_disabled() {
    let committee = Committee {
        enable_commit_recheck: false,
        ..mock_committee()
    };
    let authorities: Vec<_> = committee.authorities.keys().copied().collect();
    let genesis = Certificate::genesis(&committee);
    let genesis_parents = genesis
        .iter()
        .map(|certificate| certificate.digest())
        .collect::<BTreeSet<_>>();

    let leader_author = authorities[0];
    let supporter_a = authorities[1];
    let supporter_b = authorities[2];

    let (_, leader_round_1) = mock_certificate(leader_author, 1, genesis_parents.clone());
    let leader_header_id = leader_round_1.header.id.clone();

    let mut support_vertices = HashSet::new();
    support_vertices.insert(leader_header_id);

    let (_, support_round_3_a) = mock_certificate_with_solid_wave(
        supporter_a,
        3,
        BTreeSet::new(),
        support_vertices.clone(),
    );
    let (_, activation_round_4) =
        mock_certificate(authorities[3], 4, BTreeSet::from([leader_round_1.digest()]));
    let (_, support_round_3_b) = mock_certificate_with_solid_wave(
        supporter_b,
        3,
        BTreeSet::new(),
        support_vertices,
    );

    let (tx_waiter, rx_waiter) = channel(10);
    let (tx_primary, mut rx_primary) = channel(10);
    let (tx_output, mut rx_output) = channel(10);
    Consensus::spawn(
        committee,
        /* gc_depth */ 50,
        rx_waiter,
        tx_primary,
        tx_output,
    );
    tokio::spawn(async move { while rx_primary.recv().await.is_some() {} });

    tx_waiter.send(leader_round_1).await.unwrap();
    tx_waiter.send(support_round_3_a).await.unwrap();
    tx_waiter.send(activation_round_4).await.unwrap();
    tx_waiter.send(support_round_3_b).await.unwrap();

    let no_commit = tokio::time::timeout(std::time::Duration::from_millis(200), rx_output.recv())
        .await;
    assert!(
        no_commit.is_err(),
        "late support should not trigger a second commit check when recheck is disabled"
    );
}

#[tokio::test]
async fn fast_coin_commits_before_regular_path() {
    let committee = Committee {
        enable_fast_coin: true,
        ..mock_committee()
    };
    let authorities: Vec<_> = committee.authorities.keys().copied().collect();
    let author_to_node = authorities
        .iter()
        .copied()
        .enumerate()
        .map(|(index, authority)| (authority, index))
        .collect();
    let genesis_certs = Certificate::genesis(&committee);
    let genesis_parents = genesis_certs
        .iter()
        .map(|certificate| certificate.digest())
        .collect::<BTreeSet<_>>();

    let leader_author = authorities[0];
    let supporter_a = authorities[1];
    let supporter_b = authorities[2];

    let (_, leader_round_1) = mock_certificate(leader_author, 1, genesis_parents.clone());
    let leader_header_id = leader_round_1.header.id.clone();

    let mut support_vertices = HashSet::new();
    support_vertices.insert(leader_header_id.clone());

    let (_, support_round_2_a) = mock_certificate_with_solid_step(
        supporter_a,
        2,
        BTreeSet::new(),
        support_vertices.clone(),
    );
    let (_, support_round_2_b) = mock_certificate_with_solid_step(
        supporter_b,
        2,
        BTreeSet::new(),
        support_vertices.clone(),
    );
    let (_, activation_round_3) =
        mock_certificate(authorities[3], 3, BTreeSet::from([leader_round_1.digest()]));

    let (_tx_waiter, rx_waiter) = channel(1);
    let (tx_primary, mut rx_primary) = channel(10);
    let (tx_output, mut rx_output) = channel(10);
    let mut consensus = Consensus {
        committee: committee.clone(),
        authorities,
        author_to_node,
        gc_depth: 50,
        rx_primary: rx_waiter,
        tx_primary,
        tx_output,
        genesis: genesis_certs.clone(),
    };
    tokio::spawn(async move { while rx_primary.recv().await.is_some() {} });

    let mut state = State::new(genesis_certs);
    state.insert(leader_round_1.clone());
    state.insert(support_round_2_a.clone());

    assert!(
        consensus.fast_coin_pending_commit_check_for_round(2, &state).is_none(),
        "fast coin should not activate before the first round-3 trigger arrives"
    );

    state.insert(support_round_2_b);
    assert!(
        consensus.fast_coin_pending_commit_check_for_round(2, &state).is_none(),
        "even with enough round-2 support certificates, activation should still wait for round 3"
    );

    state.insert(activation_round_3.clone());
    let mut fast_pending = consensus
        .fast_coin_pending_commit_check_for_round(3, &state)
        .expect("the first round-3 trigger should activate the r2 -> r1 fast-coin check");
    assert_eq!(fast_pending.leader_round, 1);
    assert_eq!(fast_pending.support_round, 2);

    let committed = consensus
        .evaluate_pending_commit_check(&mut state, 3, &mut fast_pending)
        .await;
    assert!(committed, "round-3 activation should immediately commit once round-2 support is already sufficient");

    let committed_leader = rx_output.recv().await.unwrap();
    assert_eq!(committed_leader.round(), 1);
    assert_eq!(committed_leader.origin(), leader_author);

    let regular_pending = consensus.solid_pending_commit_check_for_round(4, &state);
    assert!(
        regular_pending.is_none(),
        "once fast coin commits the leader, the regular path should no longer activate"
    );
}

#[tokio::test]
async fn fast_coin_commits_via_parent_path_when_step_summary_missing() {
    let committee = Committee {
        enable_fast_coin: true,
        ..mock_committee()
    };
    let authorities: Vec<_> = committee.authorities.keys().copied().collect();
    let author_to_node = authorities
        .iter()
        .copied()
        .enumerate()
        .map(|(index, authority)| (authority, index))
        .collect();
    let genesis_certs = Certificate::genesis(&committee);
    let genesis_parents = genesis_certs
        .iter()
        .map(|certificate| certificate.digest())
        .collect::<BTreeSet<_>>();

    let leader_author = authorities[0];
    let supporter_a = authorities[1];
    let supporter_b = authorities[2];
    let leader_digest;

    let (_, leader_round_1) = mock_certificate(leader_author, 1, genesis_parents.clone());
    leader_digest = leader_round_1.digest();
    let support_parents = BTreeSet::from([leader_digest.clone()]);

    let (_, support_round_2_a) =
        mock_certificate(supporter_a, 2, support_parents.clone());
    let (_, support_round_2_b) =
        mock_certificate(supporter_b, 2, support_parents.clone());
    let (_, activation_round_3) =
        mock_certificate(authorities[3], 3, BTreeSet::from([leader_digest.clone()]));

    let (_tx_waiter, rx_waiter) = channel(1);
    let (tx_primary, mut rx_primary) = channel(10);
    let (tx_output, mut rx_output) = channel(10);
    let mut consensus = Consensus {
        committee: committee.clone(),
        authorities,
        author_to_node,
        gc_depth: 50,
        rx_primary: rx_waiter,
        tx_primary,
        tx_output,
        genesis: genesis_certs.clone(),
    };
    tokio::spawn(async move { while rx_primary.recv().await.is_some() {} });

    let mut state = State::new(genesis_certs);
    state.insert(leader_round_1.clone());
    state.insert(support_round_2_a.clone());
    state.insert(support_round_2_b.clone());
    state.insert(activation_round_3.clone());

    let mut fast_pending = consensus
        .fast_coin_pending_commit_check_for_round(3, &state)
        .expect("round 3 should still activate fast coin");
    let committed = consensus
        .evaluate_pending_commit_check(&mut state, 3, &mut fast_pending)
        .await;
    assert!(
        committed,
        "fast coin should fall back to the parent path when the solid-step summary misses the leader"
    );

    let committed_leader = rx_output.recv().await.unwrap();
    assert_eq!(committed_leader.round(), 1);
    assert_eq!(committed_leader.origin(), leader_author);
}

#[tokio::test]
async fn fast_coin_candidate_threshold_delays_commit_until_enough_candidates() {
    let committee = Committee {
        enable_fast_coin: true,
        fast_coin_candidate_threshold: 2,
        ..mock_committee()
    };
    let authorities: Vec<_> = committee.authorities.keys().copied().collect();
    let author_to_node = authorities
        .iter()
        .copied()
        .enumerate()
        .map(|(index, authority)| (authority, index))
        .collect();
    let genesis_certs = Certificate::genesis(&committee);
    let genesis_parents = genesis_certs
        .iter()
        .map(|certificate| certificate.digest())
        .collect::<BTreeSet<_>>();

    let leader_author = authorities[0];
    let second_candidate_author = authorities[1];
    let supporter_a = authorities[2];
    let supporter_b = authorities[3];

    let (_, mut leader_round_1) = mock_certificate(leader_author, 1, genesis_parents.clone());
    leader_round_1.header.id = leader_round_1.header.digest();
    let leader_header_id = leader_round_1.header.id.clone();
    let (_, mut second_candidate_round_1) =
        mock_certificate(second_candidate_author, 1, genesis_parents.clone());
    second_candidate_round_1.header.id = second_candidate_round_1.header.digest();
    let second_candidate_header_id = second_candidate_round_1.header.id.clone();

    let mut leader_only = HashSet::new();
    leader_only.insert(leader_header_id.clone());
    let mut both_candidates = leader_only.clone();
    both_candidates.insert(second_candidate_header_id);

    let (_, support_round_2_a) = mock_certificate_with_solid_step(
        supporter_a,
        2,
        BTreeSet::new(),
        leader_only.clone(),
    );
    let (_, support_round_2_b) = mock_certificate_with_solid_step(
        supporter_b,
        2,
        BTreeSet::new(),
        leader_only,
    );
    let (_, late_support_round_2_c) = mock_certificate_with_solid_step(
        leader_author,
        2,
        BTreeSet::new(),
        both_candidates.clone(),
    );
    let (_, late_support_round_2_d) = mock_certificate_with_solid_step(
        second_candidate_author,
        2,
        BTreeSet::new(),
        both_candidates,
    );
    let (_, activation_round_3) =
        mock_certificate(supporter_a, 3, BTreeSet::from([leader_round_1.digest()]));

    let (_tx_waiter, rx_waiter) = channel(1);
    let (tx_primary, mut rx_primary) = channel(10);
    let (tx_output, mut rx_output) = channel(10);
    let mut consensus = Consensus {
        committee: committee.clone(),
        authorities,
        author_to_node,
        gc_depth: 50,
        rx_primary: rx_waiter,
        tx_primary,
        tx_output,
        genesis: genesis_certs.clone(),
    };
    tokio::spawn(async move { while rx_primary.recv().await.is_some() {} });

    let mut state = State::new(genesis_certs);
    state.insert(leader_round_1.clone());
    state.insert(second_candidate_round_1);
    state.insert(support_round_2_a.clone());
    state.insert(support_round_2_b.clone());
    state.insert(activation_round_3);

    let mut pending = consensus
        .fast_coin_pending_commit_check_for_round(3, &state)
        .expect("round 3 should activate fast coin pending state");
    let committed = consensus
        .evaluate_pending_commit_check(&mut state, 3, &mut pending)
        .await;
    assert!(
        !committed,
        "fast coin should wait until enough leader-round candidates gather f+1 support"
    );

    state.insert(late_support_round_2_c);
    let committed = consensus
        .evaluate_pending_commit_check(&mut state, 2, &mut pending)
        .await;
    assert!(
        !committed,
        "one extra support certificate should still leave the second candidate below f+1"
    );

    state.insert(late_support_round_2_d);
    let committed = consensus
        .evaluate_pending_commit_check(&mut state, 2, &mut pending)
        .await;
    assert!(committed, "fast coin should commit once m supported candidates exist");

    let committed_leader = rx_output.recv().await.unwrap();
    assert_eq!(committed_leader.round(), 1);
    assert_eq!(committed_leader.origin(), leader_author);
}

#[tokio::test]
async fn solid_candidate_threshold_delays_commit_until_enough_candidates() {
    let committee = Committee {
        solid_commit_trigger_on_solid_step: true,
        solid_candidate_threshold: 2,
        ..mock_committee()
    };
    let authorities: Vec<_> = committee.authorities.keys().copied().collect();
    let author_to_node = authorities
        .iter()
        .copied()
        .enumerate()
        .map(|(index, authority)| (authority, index))
        .collect();
    let genesis_certs = Certificate::genesis(&committee);
    let genesis_parents = genesis_certs
        .iter()
        .map(|certificate| certificate.digest())
        .collect::<BTreeSet<_>>();

    let leader_author = authorities[0];
    let second_candidate_author = authorities[1];
    let supporter_a = authorities[2];
    let supporter_b = authorities[3];

    let (_, mut leader_round_1) = mock_certificate(leader_author, 1, genesis_parents.clone());
    leader_round_1.header.id = leader_round_1.header.digest();
    let leader_header_id = leader_round_1.header.id.clone();
    let (_, mut second_candidate_round_1) =
        mock_certificate(second_candidate_author, 1, genesis_parents.clone());
    second_candidate_round_1.header.id = second_candidate_round_1.header.digest();
    let second_candidate_header_id = second_candidate_round_1.header.id.clone();

    let mut leader_only = HashSet::new();
    leader_only.insert(leader_header_id.clone());
    let mut both_candidates = leader_only.clone();
    both_candidates.insert(second_candidate_header_id);

    let (_, support_round_3_a) = mock_certificate_with_solid_wave(
        supporter_a,
        3,
        BTreeSet::new(),
        leader_only.clone(),
    );
    let (_, support_round_3_b) = mock_certificate_with_solid_wave(
        supporter_b,
        3,
        BTreeSet::new(),
        leader_only,
    );
    let (_, late_support_round_3_c) = mock_certificate_with_solid_wave(
        leader_author,
        3,
        BTreeSet::new(),
        both_candidates.clone(),
    );
    let (_, late_support_round_3_d) = mock_certificate_with_solid_wave(
        second_candidate_author,
        3,
        BTreeSet::new(),
        both_candidates,
    );
    let (_, activation_round_4) =
        mock_certificate(supporter_a, 4, BTreeSet::from([leader_round_1.digest()]));

    let (_tx_waiter, rx_waiter) = channel(1);
    let (tx_primary, mut rx_primary) = channel(10);
    let (tx_output, mut rx_output) = channel(10);
    let mut consensus = Consensus {
        committee: committee.clone(),
        authorities,
        author_to_node,
        gc_depth: 50,
        rx_primary: rx_waiter,
        tx_primary,
        tx_output,
        genesis: genesis_certs.clone(),
    };
    tokio::spawn(async move { while rx_primary.recv().await.is_some() {} });

    let mut state = State::new(genesis_certs);
    state.insert(leader_round_1.clone());
    state.insert(second_candidate_round_1);
    state.insert(support_round_3_a.clone());
    state.insert(support_round_3_b.clone());
    state.insert(activation_round_4);

    let mut pending = consensus
        .solid_pending_commit_check_for_round(4, &state)
        .expect("round 4 should activate solid pending state");
    assert!(pending.candidate_gate_enabled);
    let committed = consensus
        .evaluate_pending_commit_check(&mut state, 4, &mut pending)
        .await;
    assert!(
        !committed,
        "solid path should wait until enough leader-round candidates gather f+1 support"
    );

    state.insert(late_support_round_3_c);
    let committed = consensus
        .evaluate_pending_commit_check(&mut state, 3, &mut pending)
        .await;
    assert!(
        !committed,
        "one extra support certificate should still leave the second candidate below f+1"
    );

    state.insert(late_support_round_3_d);
    let committed = consensus
        .evaluate_pending_commit_check(&mut state, 3, &mut pending)
        .await;
    assert!(committed, "solid path should commit once m supported candidates exist");

    let committed_leader = rx_output.recv().await.unwrap();
    assert_eq!(committed_leader.round(), 1);
    assert_eq!(committed_leader.origin(), leader_author);
}

#[tokio::test]
async fn default_wave_start_solid_commit_ignores_candidate_threshold() {
    let committee = Committee {
        solid_candidate_threshold: 2,
        ..mock_committee()
    };
    let authorities: Vec<_> = committee.authorities.keys().copied().collect();
    let author_to_node = authorities
        .iter()
        .copied()
        .enumerate()
        .map(|(index, authority)| (authority, index))
        .collect();
    let genesis_certs = Certificate::genesis(&committee);
    let genesis_parents = genesis_certs
        .iter()
        .map(|certificate| certificate.digest())
        .collect::<BTreeSet<_>>();

    let leader_author = authorities[0];
    let supporter_a = authorities[1];
    let supporter_b = authorities[2];

    let (_, leader_round_1) = mock_certificate(leader_author, 1, genesis_parents.clone());
    let leader_header_id = leader_round_1.header.id.clone();
    let mut leader_only = HashSet::new();
    leader_only.insert(leader_header_id);

    let (_, support_round_3_a) = mock_certificate_with_solid_wave(
        supporter_a,
        3,
        BTreeSet::new(),
        leader_only.clone(),
    );
    let (_, support_round_3_b) = mock_certificate_with_solid_wave(
        supporter_b,
        3,
        BTreeSet::new(),
        leader_only,
    );
    let (_, activation_round_5) =
        mock_certificate(authorities[3], 5, BTreeSet::from([leader_round_1.digest()]));

    let (_tx_waiter, rx_waiter) = channel(1);
    let (tx_primary, mut rx_primary) = channel(10);
    let (tx_output, mut rx_output) = channel(10);
    let mut consensus = Consensus {
        committee: committee.clone(),
        authorities,
        author_to_node,
        gc_depth: 50,
        rx_primary: rx_waiter,
        tx_primary,
        tx_output,
        genesis: genesis_certs.clone(),
    };
    tokio::spawn(async move { while rx_primary.recv().await.is_some() {} });

    let mut state = State::new(genesis_certs);
    state.insert(leader_round_1.clone());
    state.insert(support_round_3_a.clone());
    state.insert(support_round_3_b.clone());
    state.insert(activation_round_5);

    let mut pending = consensus
        .solid_pending_commit_check_for_round(5, &state)
        .expect("round 5 should activate the default solid fallback");
    assert!(!pending.candidate_gate_enabled);
    let committed = consensus
        .evaluate_pending_commit_check(&mut state, 5, &mut pending)
        .await;
    assert!(
        committed,
        "default round-5 solid fallback should ignore solid candidate threshold once support stake is sufficient"
    );

    let committed_leader = rx_output.recv().await.unwrap();
    assert_eq!(committed_leader.round(), 1);
    assert_eq!(committed_leader.origin(), leader_author);
}

#[test]
fn wave_start_fallback_clears_candidate_gate_for_existing_solid_pending() {
    let committee = Committee {
        solid_commit_trigger_on_solid_step: true,
        solid_candidate_threshold: 2,
        ..mock_committee()
    };
    let authorities: Vec<_> = committee.authorities.keys().copied().collect();
    let author_to_node = authorities
        .iter()
        .copied()
        .enumerate()
        .map(|(index, authority)| (authority, index))
        .collect();
    let genesis_certs = Certificate::genesis(&committee);
    let genesis_parents = genesis_certs
        .iter()
        .map(|certificate| certificate.digest())
        .collect::<BTreeSet<_>>();

    let (_, leader_round_1) = mock_certificate(authorities[0], 1, genesis_parents.clone());
    let (_, activation_round_4) =
        mock_certificate(authorities[1], 4, BTreeSet::from([leader_round_1.digest()]));
    let (_, activation_round_5) =
        mock_certificate(authorities[2], 5, BTreeSet::from([leader_round_1.digest()]));

    let (_tx_waiter, rx_waiter) = channel(1);
    let (tx_primary, _rx_primary) = channel(10);
    let (tx_output, _rx_output) = channel(10);
    let consensus = Consensus {
        committee,
        authorities,
        author_to_node,
        gc_depth: 50,
        rx_primary: rx_waiter,
        tx_primary,
        tx_output,
        genesis: genesis_certs.clone(),
    };

    let mut state = State::new(genesis_certs);
    state.insert(leader_round_1);
    state.insert(activation_round_4);

    let mut pending = consensus
        .solid_pending_commit_check_for_round(4, &state)
        .expect("round 4 should activate the early solid-step path");
    assert!(pending.candidate_gate_enabled);

    state.insert(activation_round_5);
    let fallback_pending = consensus
        .solid_pending_commit_check_for_round(5, &state)
        .expect("round 5 should still activate the default solid fallback");
    assert!(!fallback_pending.candidate_gate_enabled);

    pending.candidate_gate_enabled &= fallback_pending.candidate_gate_enabled;
    assert!(
        !pending.candidate_gate_enabled,
        "the default round-5 fallback must clear the earlier solid candidate gate"
    );
}
