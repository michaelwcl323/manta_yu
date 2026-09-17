// Copyright(C) Facebook, Inc. and its affiliates.
use super::*;
use crate::common::{batch_digest, committee_with_base_port, keys, listener, serialized_batch};
use std::fs;
use tokio::sync::mpsc::channel;

#[tokio::test]
async fn synchronize() {
    let (tx_message, rx_message) = channel(1);

    let mut keys = keys();
    let (name, _) = keys.pop().unwrap();
    let id = 0;
    let committee = committee_with_base_port(9_000);

    // Create a new test store.
    let path = ".db_test_synchronize";
    let _ = fs::remove_dir_all(path);
    let store = Store::new(path).unwrap();

    // Spawn a `Synchronizer` instance.
    Synchronizer::spawn(
        name,
        id,
        committee.clone(),
        store.clone(),
        /* gc_depth */ 50, // Not used in this test.
        /* sync_retry_delay */ 1_000_000, // Ensure it is not triggered.
        /* sync_retry_nodes */ 3, // Not used in this test.
        rx_message,
    );

    // Spawn a listener to receive our batch requests.
    let (target, _) = keys.pop().unwrap();
    let address = committee.worker(&target, &id).unwrap().worker_to_worker;
    let missing = vec![batch_digest()];
    let message = WorkerMessage::BatchRequest(missing.clone(), name);
    let serialized = bincode::serialize(&message).unwrap();
    let handle = listener(address, Some(Bytes::from(serialized)));

    // Send a sync request.
    let message = PrimaryWorkerMessage::Synchronize(missing, target);
    tx_message.send(message).await.unwrap();

    // Ensure the target receives the sync request.
    assert!(handle.await.is_ok());
}

#[tokio::test]
async fn synchronize_existing_batch_renotifies_primary() {
    let (tx_message, rx_message) = channel(1);
    let (name, _) = keys().pop().unwrap();
    let id = 0;
    let committee = committee_with_base_port(10_000);
    let path = ".db_test_synchronize_existing";
    let _ = fs::remove_dir_all(path);
    let mut store = Store::new(path).unwrap();
    let digest = batch_digest();
    store.write(digest.to_vec(), serialized_batch()).await;

    Synchronizer::spawn(
        name,
        id,
        committee.clone(),
        store,
        50,
        1_000,
        3,
        rx_message,
    );

    let primary_address = committee.primary(&name).unwrap().worker_to_primary;
    let expected = bincode::serialize(&WorkerPrimaryMessage::OthersBatch(digest.clone(), id)).unwrap();
    let handle = listener(primary_address, Some(Bytes::from(expected)));
    tx_message
        .send(PrimaryWorkerMessage::Synchronize(vec![digest], name))
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(3), handle)
        .await
        .expect("Primary did not receive the stored batch digest")
        .unwrap();
}
