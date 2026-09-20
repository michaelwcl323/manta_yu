// Copyright(C) Facebook, Inc. and its affiliates.
use super::*;
use crate::common::{
    attack_committee, certificate, committee, committee_with_base_port, header, headers, keys,
    listener, votes,
};
use crate::messages::set_author_bit;
use crypto::Signature;
use futures::future::try_join_all;
use std::collections::{BTreeSet, HashSet};
use std::fs;
use tokio::sync::mpsc::channel;

#[tokio::test]
async fn process_header() {
    let mut keys = keys();
    let _ = keys.pop().unwrap(); // Skip the header' author.
    let (name, secret) = keys.pop().unwrap();
    let mut signature_service = SignatureService::new(secret);

    let committee = committee_with_base_port(13_000);

    let (tx_sync_headers, _rx_sync_headers) = channel(1);
    let (tx_sync_certificates, _rx_sync_certificates) = channel(1);
    let (tx_primary_messages, rx_primary_messages) = channel(1);
    let (_tx_headers_loopback, rx_headers_loopback) = channel(1);
    let (_tx_certificates_loopback, rx_certificates_loopback) = channel(1);
    let (_tx_headers, rx_headers) = channel(1);
    let (tx_consensus, _rx_consensus) = channel(1);
    let (tx_parents, _rx_parents) = channel(1);

    // Create a new test store.
    let path = ".db_test_process_header";
    let _ = fs::remove_dir_all(path);
    let mut store = Store::new(path).unwrap();

    // Make the vote we expect to receive.
    let expected = Vote::new(&header(), &name, &mut signature_service).await;

    // Spawn a listener to receive the vote.
    let address = committee
        .primary(&header().author)
        .unwrap()
        .primary_to_primary;
    let handle = listener(address);

    // Make a synchronizer for the core.
    let synchronizer = Synchronizer::new(
        name,
        &committee,
        store.clone(),
        /* tx_header_waiter */ tx_sync_headers,
        /* tx_certificate_waiter */ tx_sync_certificates,
    );

    // Spawn the core.
    Core::spawn(
        name,
        committee,
        store.clone(),
        synchronizer,
        signature_service,
        /* consensus_round */ Arc::new(AtomicU64::new(0)),
        /* gc_depth */ 50,
        /* rx_primaries */ rx_primary_messages,
        /* rx_header_waiter */ rx_headers_loopback,
        /* rx_certificate_waiter */ rx_certificates_loopback,
        /* rx_proposer */ rx_headers,
        tx_consensus,
        /* tx_proposer */ tx_parents,
        std::sync::Arc::new(std::sync::Mutex::new(
            crate::support_visibility::SupportVisibilityGate::new(),
        )),
    );

    // Send a header to the core.
    tx_primary_messages
        .send(PrimaryMessage::Header(header()))
        .await
        .unwrap();

    // Ensure the listener correctly received the vote.
    let received = handle.await.unwrap();
    match bincode::deserialize(&received).unwrap() {
        PrimaryMessage::Vote(x) => assert_eq!(x, expected),
        x => panic!("Unexpected message: {:?}", x),
    }

    // Ensure the header is correctly stored.
    let stored = store
        .read(header().id.to_vec())
        .await
        .unwrap()
        .map(|x| bincode::deserialize(&x).unwrap());
    assert_eq!(stored, Some(header()));
}

#[tokio::test]
async fn process_header_missing_parent() {
    let (name, secret) = keys().pop().unwrap();
    let signature_service = SignatureService::new(secret);

    let (tx_sync_headers, _rx_sync_headers) = channel(1);
    let (tx_sync_certificates, _rx_sync_certificates) = channel(1);
    let (tx_primary_messages, rx_primary_messages) = channel(1);
    let (_tx_headers_loopback, rx_headers_loopback) = channel(1);
    let (_tx_certificates_loopback, rx_certificates_loopback) = channel(1);
    let (_tx_headers, rx_headers) = channel(1);
    let (tx_consensus, _rx_consensus) = channel(1);
    let (tx_parents, _rx_parents) = channel(1);

    // Create a new test store.
    let path = ".db_test_process_header_missing_parent";
    let _ = fs::remove_dir_all(path);
    let mut store = Store::new(path).unwrap();

    // Make a synchronizer for the core.
    let synchronizer = Synchronizer::new(
        name,
        &committee(),
        store.clone(),
        /* tx_header_waiter */ tx_sync_headers,
        /* tx_certificate_waiter */ tx_sync_certificates,
    );

    // Spawn the core.
    Core::spawn(
        name,
        committee(),
        store.clone(),
        synchronizer,
        signature_service,
        /* consensus_round */ Arc::new(AtomicU64::new(0)),
        /* gc_depth */ 50,
        /* rx_primaries */ rx_primary_messages,
        /* rx_header_waiter */ rx_headers_loopback,
        /* rx_certificate_waiter */ rx_certificates_loopback,
        /* rx_proposer */ rx_headers,
        tx_consensus,
        /* tx_proposer */ tx_parents,
        std::sync::Arc::new(std::sync::Mutex::new(
            crate::support_visibility::SupportVisibilityGate::new(),
        )),
    );

    // Send a header to the core.
    let header = Header {
        parents: [Digest::default()].iter().cloned().collect(),
        ..header()
    };
    let id = header.id.clone();
    tx_primary_messages
        .send(PrimaryMessage::Header(header))
        .await
        .unwrap();

    // Ensure the header is not stored.
    assert!(store.read(id.to_vec()).await.unwrap().is_none());
}

#[tokio::test]
async fn process_header_missing_payload() {
    let (name, secret) = keys().pop().unwrap();
    let signature_service = SignatureService::new(secret);

    let (tx_sync_headers, _rx_sync_headers) = channel(1);
    let (tx_sync_certificates, _rx_sync_certificates) = channel(1);
    let (tx_primary_messages, rx_primary_messages) = channel(1);
    let (_tx_headers_loopback, rx_headers_loopback) = channel(1);
    let (_tx_certificates_loopback, rx_certificates_loopback) = channel(1);
    let (_tx_headers, rx_headers) = channel(1);
    let (tx_consensus, _rx_consensus) = channel(1);
    let (tx_parents, _rx_parents) = channel(1);

    // Create a new test store.
    let path = ".db_test_process_header_missing_payload";
    let _ = fs::remove_dir_all(path);
    let mut store = Store::new(path).unwrap();

    // Make a synchronizer for the core.
    let synchronizer = Synchronizer::new(
        name,
        &committee(),
        store.clone(),
        /* tx_header_waiter */ tx_sync_headers,
        /* tx_certificate_waiter */ tx_sync_certificates,
    );

    // Spawn the core.
    Core::spawn(
        name,
        committee(),
        store.clone(),
        synchronizer,
        signature_service,
        /* consensus_round */ Arc::new(AtomicU64::new(0)),
        /* gc_depth */ 50,
        /* rx_primaries */ rx_primary_messages,
        /* rx_header_waiter */ rx_headers_loopback,
        /* rx_certificate_waiter */ rx_certificates_loopback,
        /* rx_proposer */ rx_headers,
        tx_consensus,
        /* tx_proposer */ tx_parents,
        std::sync::Arc::new(std::sync::Mutex::new(
            crate::support_visibility::SupportVisibilityGate::new(),
        )),
    );

    // Send a header to the core.
    let header = Header {
        payload: [(Digest::default(), 0)].iter().cloned().collect(),
        ..header()
    };
    let id = header.id.clone();
    tx_primary_messages
        .send(PrimaryMessage::Header(header))
        .await
        .unwrap();

    // Ensure the header is not stored.
    assert!(store.read(id.to_vec()).await.unwrap().is_none());
}

#[tokio::test]
async fn process_header_rejects_wave_boundary_without_quorum_back_link() {
    fn make_header_with_metadata(
        committee: &config::Committee,
        author: PublicKey,
        secret: &crypto::SecretKey,
        round: Round,
        parents: BTreeSet<Digest>,
        solid_step_merged: HashSet<Digest>,
        solid_wave_merged: HashSet<Digest>,
        wave_back_link_target_round: Round,
        reachable_authors: &[PublicKey],
    ) -> Header {
        let mut wave_back_link_author_bitmap = vec![0; committee.authority_bitmap_len()];
        for reachable_author in reachable_authors {
            if let Some(index) = committee.authority_index(reachable_author) {
                set_author_bit(&mut wave_back_link_author_bitmap, index);
            }
        }
        let header = Header {
            author,
            round,
            parents,
            solid_step_vertices: solid_step_merged.clone(),
            solid_step_vertices_merged: solid_step_merged,
            solid_wave_vertices: solid_wave_merged.clone(),
            solid_wave_vertices_merged: solid_wave_merged,
            wave_back_link_target_round,
            wave_back_link_author_bitmap,
            ..Header::default()
        };
        Header {
            id: header.digest(),
            signature: Signature::new(&header.digest(), secret),
            ..header
        }
    }

    let mut authorities = keys();
    let (local_name, local_secret) = authorities.pop().unwrap();
    let r2_authorities = authorities;

    let signature_service = SignatureService::new(local_secret);
    let (tx_sync_headers, _rx_sync_headers) = channel(1);
    let (tx_sync_certificates, _rx_sync_certificates) = channel(1);
    let (tx_primary_messages, rx_primary_messages) = channel(1);
    let (_tx_headers_loopback, rx_headers_loopback) = channel(1);
    let (_tx_certificates_loopback, rx_certificates_loopback) = channel(1);
    let (_tx_headers, rx_headers) = channel(1);
    let (tx_consensus, _rx_consensus) = channel(1);
    let (tx_parents, _rx_parents) = channel(1);

    let path = ".db_test_process_header_rejects_wave_boundary_without_quorum_back_link";
    let _ = fs::remove_dir_all(path);
    let mut store = Store::new(path).unwrap();
    let committee = committee();

    let synchronizer = Synchronizer::new(
        local_name,
        &committee,
        store.clone(),
        /* tx_header_waiter */ tx_sync_headers,
        /* tx_certificate_waiter */ tx_sync_certificates,
    );

    Core::spawn(
        local_name,
        committee.clone(),
        store.clone(),
        synchronizer,
        signature_service,
        /* consensus_round */ Arc::new(AtomicU64::new(0)),
        /* gc_depth */ 50,
        /* rx_primaries */ rx_primary_messages,
        /* rx_header_waiter */ rx_headers_loopback,
        /* rx_certificate_waiter */ rx_certificates_loopback,
        /* rx_proposer */ rx_headers,
        tx_consensus,
        /* tx_proposer */ tx_parents,
        std::sync::Arc::new(std::sync::Mutex::new(
            crate::support_visibility::SupportVisibilityGate::new(),
        )),
    );

    let r2_headers: Vec<_> = r2_authorities
        .iter()
        .map(|(author, secret)| {
            make_header_with_metadata(
                &committee,
                *author,
                secret,
                2,
                BTreeSet::new(),
                HashSet::new(),
                HashSet::new(),
                2,
                &[],
            )
        })
        .collect();
    let r2_certificates: Vec<_> = r2_headers.iter().map(certificate).collect();
    for cert in &r2_certificates {
        let bytes = bincode::serialize(cert).unwrap();
        store.write(cert.digest().to_vec(), bytes).await;
    }

    let r3_digests: HashSet<_> = r2_authorities
        .iter()
        .map(|(author, secret)| {
            make_header_with_metadata(
                &committee,
                *author,
                secret,
                3,
                BTreeSet::new(),
                HashSet::new(),
                HashSet::new(),
                2,
                &r2_authorities.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
            )
            .digest()
        })
        .collect();
    let only_two_r2_digests: HashSet<_> = r2_certificates
        .iter()
        .take(2)
        .map(|cert| cert.digest())
        .collect();
    let only_two_r2_authors: Vec<_> = r2_authorities
        .iter()
        .take(2)
        .map(|(author, _)| *author)
        .collect();

    let r4_certificates: Vec<_> = r2_authorities
        .iter()
        .map(|(author, secret)| {
            let header = make_header_with_metadata(
                &committee,
                *author,
                secret,
                4,
                BTreeSet::new(),
                r3_digests.clone(),
                only_two_r2_digests.clone(),
                2,
                &only_two_r2_authors,
            );
            certificate(&header)
        })
        .collect();
    for cert in &r4_certificates {
        let bytes = bincode::serialize(cert).unwrap();
        store.write(cert.digest().to_vec(), bytes).await;
    }

    let rejected_header = make_header_with_metadata(
        &committee,
        r2_authorities[0].0,
        &r2_authorities[0].1,
        5,
        r4_certificates.iter().map(|cert| cert.digest()).collect(),
        HashSet::new(),
        HashSet::new(),
        2,
        &only_two_r2_authors,
    );
    let rejected_id = rejected_header.id.clone();

    tx_primary_messages
        .send(PrimaryMessage::Header(rejected_header))
        .await
        .unwrap();

    assert!(store.read(rejected_id.to_vec()).await.unwrap().is_none());
}

#[tokio::test]
async fn process_header_accepts_wave_boundary_with_indirect_quorum_back_link() {
    fn make_header_with_metadata(
        committee: &config::Committee,
        author: PublicKey,
        secret: &crypto::SecretKey,
        round: Round,
        parents: BTreeSet<Digest>,
        solid_step_merged: HashSet<Digest>,
        solid_wave_merged: HashSet<Digest>,
        wave_back_link_target_round: Round,
        reachable_authors: &[PublicKey],
    ) -> Header {
        let mut wave_back_link_author_bitmap = vec![0; committee.authority_bitmap_len()];
        for reachable_author in reachable_authors {
            if let Some(index) = committee.authority_index(reachable_author) {
                set_author_bit(&mut wave_back_link_author_bitmap, index);
            }
        }
        let header = Header {
            author,
            round,
            parents,
            solid_step_vertices: solid_step_merged.clone(),
            solid_step_vertices_merged: solid_step_merged,
            solid_wave_vertices: solid_wave_merged.clone(),
            solid_wave_vertices_merged: solid_wave_merged,
            wave_back_link_target_round,
            wave_back_link_author_bitmap,
            ..Header::default()
        };
        Header {
            id: header.digest(),
            signature: Signature::new(&header.digest(), secret),
            ..header
        }
    }

    let mut authorities = keys();
    let (local_name, local_secret) = authorities.pop().unwrap();
    let r2_authorities = authorities;
    let all_r2_authors: Vec<_> = r2_authorities.iter().map(|(author, _)| *author).collect();

    let (tx_sync_headers, _rx_sync_headers) = channel(1);
    let (tx_sync_certificates, _rx_sync_certificates) = channel(1);
    let (tx_primary_messages, rx_primary_messages) = channel(1);
    let (_tx_headers_loopback, rx_headers_loopback) = channel(1);
    let (_tx_certificates_loopback, rx_certificates_loopback) = channel(1);
    let (_tx_headers, rx_headers) = channel(1);
    let (tx_consensus, _rx_consensus) = channel(1);
    let (tx_parents, _rx_parents) = channel(1);

    let path = ".db_test_process_header_accepts_wave_boundary_with_indirect_quorum_back_link";
    let _ = fs::remove_dir_all(path);
    let mut store = Store::new(path).unwrap();
    let committee = committee_with_base_port(13_200);

    let r2_certificates: Vec<_> = r2_authorities
        .iter()
        .map(|(author, secret)| {
            let header = make_header_with_metadata(
                &committee,
                *author,
                secret,
                2,
                BTreeSet::new(),
                HashSet::new(),
                HashSet::new(),
                2,
                &[],
            );
            certificate(&header)
        })
        .collect();
    for cert in &r2_certificates {
        let bytes = bincode::serialize(cert).unwrap();
        store.write(cert.digest().to_vec(), bytes).await;
    }

    let r3_digests: HashSet<_> = r2_authorities
        .iter()
        .map(|(author, secret)| {
            make_header_with_metadata(
                &committee,
                *author,
                secret,
                3,
                BTreeSet::new(),
                HashSet::new(),
                HashSet::new(),
                2,
                &all_r2_authors,
            )
            .digest()
        })
        .collect();

    let r4_certificates: Vec<_> = r2_authorities
        .iter()
        .map(|(author, secret)| {
            let header = make_header_with_metadata(
                &committee,
                *author,
                secret,
                4,
                BTreeSet::new(),
                r3_digests.clone(),
                HashSet::new(),
                2,
                &all_r2_authors,
            );
            certificate(&header)
        })
        .collect();
    for cert in &r4_certificates {
        let bytes = bincode::serialize(cert).unwrap();
        store.write(cert.digest().to_vec(), bytes).await;
    }

    let accepted_header = make_header_with_metadata(
        &committee,
        r2_authorities[0].0,
        &r2_authorities[0].1,
        5,
        r4_certificates.iter().map(|cert| cert.digest()).collect(),
        HashSet::new(),
        HashSet::new(),
        2,
        &all_r2_authors,
    );
    let accepted_id = accepted_header.id.clone();
    let mut signature_service = SignatureService::new(local_secret);
    let expected = Vote::new(&accepted_header, &local_name, &mut signature_service).await;
    let address = committee
        .primary(&accepted_header.author)
        .unwrap()
        .primary_to_primary;
    let handle = listener(address);
    let synchronizer = Synchronizer::new(
        local_name,
        &committee,
        store.clone(),
        /* tx_header_waiter */ tx_sync_headers,
        /* tx_certificate_waiter */ tx_sync_certificates,
    );

    Core::spawn(
        local_name,
        committee.clone(),
        store.clone(),
        synchronizer,
        signature_service,
        /* consensus_round */ Arc::new(AtomicU64::new(0)),
        /* gc_depth */ 50,
        /* rx_primaries */ rx_primary_messages,
        /* rx_header_waiter */ rx_headers_loopback,
        /* rx_certificate_waiter */ rx_certificates_loopback,
        /* rx_proposer */ rx_headers,
        tx_consensus,
        /* tx_proposer */ tx_parents,
        std::sync::Arc::new(std::sync::Mutex::new(
            crate::support_visibility::SupportVisibilityGate::new(),
        )),
    );

    tx_primary_messages
        .send(PrimaryMessage::Header(accepted_header.clone()))
        .await
        .unwrap();

    let received = handle.await.unwrap();
    match bincode::deserialize(&received).unwrap() {
        PrimaryMessage::Vote(x) => assert_eq!(x, expected),
        x => panic!("Unexpected message: {:?}", x),
    }

    let stored = store
        .read(accepted_id.to_vec())
        .await
        .unwrap()
        .map(|x| bincode::deserialize(&x).unwrap());
    assert_eq!(stored, Some(accepted_header));
}

#[tokio::test]
async fn process_header_accepts_wave_boundary_with_direct_quorum_back_link() {
    fn make_header_with_metadata(
        committee: &config::Committee,
        author: PublicKey,
        secret: &crypto::SecretKey,
        round: Round,
        parents: BTreeSet<Digest>,
        solid_step_merged: HashSet<Digest>,
        solid_wave_merged: HashSet<Digest>,
        wave_back_link_target_round: Round,
        reachable_authors: &[PublicKey],
    ) -> Header {
        let mut wave_back_link_author_bitmap = vec![0; committee.authority_bitmap_len()];
        for reachable_author in reachable_authors {
            if let Some(index) = committee.authority_index(reachable_author) {
                set_author_bit(&mut wave_back_link_author_bitmap, index);
            }
        }
        let header = Header {
            author,
            round,
            parents,
            solid_step_vertices: solid_step_merged.clone(),
            solid_step_vertices_merged: solid_step_merged,
            solid_wave_vertices: solid_wave_merged.clone(),
            solid_wave_vertices_merged: solid_wave_merged,
            wave_back_link_target_round,
            wave_back_link_author_bitmap,
            ..Header::default()
        };
        Header {
            id: header.digest(),
            signature: Signature::new(&header.digest(), secret),
            ..header
        }
    }

    let mut authorities = keys();
    let (local_name, local_secret) = authorities.pop().unwrap();
    let r2_authorities = authorities;
    let all_r2_authors: Vec<_> = r2_authorities.iter().map(|(author, _)| *author).collect();

    let (tx_sync_headers, _rx_sync_headers) = channel(1);
    let (tx_sync_certificates, _rx_sync_certificates) = channel(1);
    let (tx_primary_messages, rx_primary_messages) = channel(1);
    let (_tx_headers_loopback, rx_headers_loopback) = channel(1);
    let (_tx_certificates_loopback, rx_certificates_loopback) = channel(1);
    let (_tx_headers, rx_headers) = channel(1);
    let (tx_consensus, _rx_consensus) = channel(1);
    let (tx_parents, _rx_parents) = channel(1);

    let path = ".db_test_process_header_accepts_wave_boundary_with_direct_quorum_back_link";
    let _ = fs::remove_dir_all(path);
    let mut store = Store::new(path).unwrap();
    let committee = committee_with_base_port(13_300);

    let r2_certificates: Vec<_> = r2_authorities
        .iter()
        .map(|(author, secret)| {
            let header = make_header_with_metadata(
                &committee,
                *author,
                secret,
                2,
                BTreeSet::new(),
                HashSet::new(),
                HashSet::new(),
                2,
                &[],
            );
            certificate(&header)
        })
        .collect();
    for cert in &r2_certificates {
        let bytes = bincode::serialize(cert).unwrap();
        store.write(cert.digest().to_vec(), bytes).await;
    }

    let r3_digests: HashSet<_> = r2_authorities
        .iter()
        .map(|(author, secret)| {
            make_header_with_metadata(
                &committee,
                *author,
                secret,
                3,
                BTreeSet::new(),
                HashSet::new(),
                HashSet::new(),
                2,
                &[],
            )
            .digest()
        })
        .collect();

    let r4_certificates: Vec<_> = r2_authorities
        .iter()
        .map(|(author, secret)| {
            let header = make_header_with_metadata(
                &committee,
                *author,
                secret,
                4,
                BTreeSet::new(),
                r3_digests.clone(),
                HashSet::new(),
                2,
                &[],
            );
            certificate(&header)
        })
        .collect();
    for cert in &r4_certificates {
        let bytes = bincode::serialize(cert).unwrap();
        store.write(cert.digest().to_vec(), bytes).await;
    }

    let accepted_header = make_header_with_metadata(
        &committee,
        r2_authorities[0].0,
        &r2_authorities[0].1,
        5,
        r4_certificates
            .iter()
            .map(|cert| cert.digest())
            .chain(r2_certificates.iter().map(|cert| cert.digest()))
            .collect(),
        HashSet::new(),
        HashSet::new(),
        2,
        &all_r2_authors,
    );
    let accepted_id = accepted_header.id.clone();
    let mut signature_service = SignatureService::new(local_secret);
    let expected = Vote::new(&accepted_header, &local_name, &mut signature_service).await;
    let address = committee
        .primary(&accepted_header.author)
        .unwrap()
        .primary_to_primary;
    let handle = listener(address);
    let synchronizer = Synchronizer::new(
        local_name,
        &committee,
        store.clone(),
        /* tx_header_waiter */ tx_sync_headers,
        /* tx_certificate_waiter */ tx_sync_certificates,
    );

    Core::spawn(
        local_name,
        committee.clone(),
        store.clone(),
        synchronizer,
        signature_service,
        /* consensus_round */ Arc::new(AtomicU64::new(0)),
        /* gc_depth */ 50,
        /* rx_primaries */ rx_primary_messages,
        /* rx_header_waiter */ rx_headers_loopback,
        /* rx_certificate_waiter */ rx_certificates_loopback,
        /* rx_proposer */ rx_headers,
        tx_consensus,
        /* tx_proposer */ tx_parents,
        std::sync::Arc::new(std::sync::Mutex::new(
            crate::support_visibility::SupportVisibilityGate::new(),
        )),
    );

    tx_primary_messages
        .send(PrimaryMessage::Header(accepted_header.clone()))
        .await
        .unwrap();

    let received = handle.await.unwrap();
    match bincode::deserialize(&received).unwrap() {
        PrimaryMessage::Vote(x) => assert_eq!(x, expected),
        x => panic!("Unexpected message: {:?}", x),
    }

    let stored = store
        .read(accepted_id.to_vec())
        .await
        .unwrap()
        .map(|x| bincode::deserialize(&x).unwrap());
    assert_eq!(stored, Some(accepted_header));
}

#[tokio::test]
async fn process_votes() {
    let (name, secret) = keys().pop().unwrap();
    let signature_service = SignatureService::new(secret);

    let committee = committee_with_base_port(13_100);

    let (tx_sync_headers, _rx_sync_headers) = channel(1);
    let (tx_sync_certificates, _rx_sync_certificates) = channel(1);
    let (tx_primary_messages, rx_primary_messages) = channel(1);
    let (_tx_headers_loopback, rx_headers_loopback) = channel(1);
    let (_tx_certificates_loopback, rx_certificates_loopback) = channel(1);
    let (_tx_headers, rx_headers) = channel(1);
    let (tx_consensus, _rx_consensus) = channel(1);
    let (tx_parents, _rx_parents) = channel(1);

    // Create a new test store.
    let path = ".db_test_process_vote";
    let _ = fs::remove_dir_all(path);
    let store = Store::new(path).unwrap();

    // Make a synchronizer for the core.
    let synchronizer = Synchronizer::new(
        name,
        &committee,
        store.clone(),
        /* tx_header_waiter */ tx_sync_headers,
        /* tx_certificate_waiter */ tx_sync_certificates,
    );

    // Spawn the core.
    Core::spawn(
        name,
        committee.clone(),
        store.clone(),
        synchronizer,
        signature_service,
        /* consensus_round */ Arc::new(AtomicU64::new(0)),
        /* gc_depth */ 50,
        /* rx_primaries */ rx_primary_messages,
        /* rx_header_waiter */ rx_headers_loopback,
        /* rx_certificate_waiter */ rx_certificates_loopback,
        /* rx_proposer */ rx_headers,
        tx_consensus,
        /* tx_proposer */ tx_parents,
        std::sync::Arc::new(std::sync::Mutex::new(
            crate::support_visibility::SupportVisibilityGate::new(),
        )),
    );

    // Make the certificate we expect to receive.
    let expected = certificate(&Header::default());

    // Spawn all listeners to receive our newly formed certificate.
    let handles: Vec<_> = committee
        .others_primaries(&name)
        .iter()
        .map(|(_, address)| listener(address.primary_to_primary))
        .collect();

    // Send a votes to the core.
    for vote in votes(&Header::default()) {
        tx_primary_messages
            .send(PrimaryMessage::Vote(vote))
            .await
            .unwrap();
    }

    // Ensure all listeners got the certificate.
    for received in try_join_all(handles).await.unwrap() {
        match bincode::deserialize(&received).unwrap() {
            PrimaryMessage::Certificate(x) => assert_eq!(x, expected),
            x => panic!("Unexpected message: {:?}", x),
        }
    }
}

#[tokio::test]
async fn process_certificates() {
    let (name, secret) = keys().pop().unwrap();
    let signature_service = SignatureService::new(secret);

    let (tx_sync_headers, _rx_sync_headers) = channel(1);
    let (tx_sync_certificates, _rx_sync_certificates) = channel(1);
    let (tx_primary_messages, rx_primary_messages) = channel(3);
    let (_tx_headers_loopback, rx_headers_loopback) = channel(1);
    let (_tx_certificates_loopback, rx_certificates_loopback) = channel(1);
    let (_tx_headers, rx_headers) = channel(1);
    let (tx_consensus, mut rx_consensus) = channel(3);
    let (tx_parents, mut rx_parents) = channel(1);

    // Create a new test store.
    let path = ".db_test_process_certificates";
    let _ = fs::remove_dir_all(path);
    let mut store = Store::new(path).unwrap();

    // Make a synchronizer for the core.
    let synchronizer = Synchronizer::new(
        name,
        &committee(),
        store.clone(),
        /* tx_header_waiter */ tx_sync_headers,
        /* tx_certificate_waiter */ tx_sync_certificates,
    );

    // Spawn the core.
    Core::spawn(
        name,
        committee(),
        store.clone(),
        synchronizer,
        signature_service,
        /* consensus_round */ Arc::new(AtomicU64::new(0)),
        /* gc_depth */ 50,
        /* rx_primaries */ rx_primary_messages,
        /* rx_header_waiter */ rx_headers_loopback,
        /* rx_certificate_waiter */ rx_certificates_loopback,
        /* rx_proposer */ rx_headers,
        tx_consensus,
        /* tx_proposer */ tx_parents,
        std::sync::Arc::new(std::sync::Mutex::new(
            crate::support_visibility::SupportVisibilityGate::new(),
        )),
    );

    // Send enough certificates to the core.
    let certificates: Vec<_> = headers()
        .iter()
        .take(3)
        .map(|header| certificate(header))
        .collect();

    for x in certificates.clone() {
        tx_primary_messages
            .send(PrimaryMessage::Certificate(x))
            .await
            .unwrap();
    }

    // Ensure the core sends the parents of the certificates to the proposer.
    let received = rx_parents.recv().await.unwrap();
    let parents = ProposalParents::from(
        certificates
            .iter()
            .map(|x| x.digest())
            .collect::<Vec<_>>(),
    );
    assert_eq!(received, (parents, 1));

    // Ensure the core sends the certificates to the consensus.
    for x in certificates.clone() {
        let received = rx_consensus.recv().await.unwrap();
        assert_eq!(received, x);
    }

    // Ensure the certificates are stored.
    for x in &certificates {
        let stored = store.read(x.digest().to_vec()).await.unwrap();
        let serialized = bincode::serialize(x).unwrap();
        assert_eq!(stored, Some(serialized));
    }
}

#[test]
fn selective_attack_keeps_only_minimal_cross_group_senders() {
    let committee = attack_committee(3);
    let authorities: Vec<_> = committee.authorities.keys().copied().collect();

    let sender_same_group = authorities[1];
    let sender_other_group_allowed = authorities[2];
    let sender_other_group_blocked = authorities[3];
    let recipient = authorities[0];

    assert!(committee.selective_attack_allows_sender_to_recipient(
        &sender_same_group,
        &recipient
    ));
    assert!(committee.selective_attack_allows_sender_to_recipient(
        &sender_other_group_allowed,
        &recipient
    ));
    assert!(!committee.selective_attack_allows_sender_to_recipient(
        &sender_other_group_blocked,
        &recipient
    ));
}

#[test]
fn selective_attack_cuts_all_cross_group_senders_at_local_coverage() {
    let committee = attack_committee(2);
    let authorities: Vec<_> = committee.authorities.keys().copied().collect();
    let recipient = authorities[0];

    assert_eq!(committee.selective_attack_cross_group_sender_limit(&recipient), 0);
    assert!(!committee.selective_attack_allows_sender_to_recipient(
        &authorities[2],
        &recipient
    ));
}
