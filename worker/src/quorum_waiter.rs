// Copyright(C) Facebook, Inc. and its affiliates.
use crate::processor::SerializedBatchMessage;
use config::{Committee, Stake};
use crypto::PublicKey;
use futures::stream::futures_unordered::FuturesUnordered;
use futures::stream::StreamExt as _;
use network::CancelHandler;
use tokio::sync::mpsc::{Receiver, Sender};

#[cfg(test)]
#[path = "tests/quorum_waiter_tests.rs"]
pub mod quorum_waiter_tests;

#[derive(Debug)]
pub struct QuorumWaiterMessage {
    /// A serialized `WorkerMessage::Batch` message.
    pub batch: SerializedBatchMessage,
    /// The cancel handlers to receive the acknowledgements of our broadcast.
    pub handlers: Vec<(PublicKey, CancelHandler)>,
}

/// The QuorumWaiter waits for 2f authorities to acknowledge reception of a batch.
pub struct QuorumWaiter {
    /// The committee information.
    committee: Committee,
    /// The stake of this authority.
    stake: Stake,
    /// Input Channel to receive commands.
    rx_message: Receiver<QuorumWaiterMessage>,
    /// Channel to deliver batches for which we have enough acknowledgements.
    tx_batch: Sender<SerializedBatchMessage>,
}

impl QuorumWaiter {
    /// Spawn a new QuorumWaiter.
    pub fn spawn(
        committee: Committee,
        stake: Stake,
        rx_message: Receiver<QuorumWaiterMessage>,
        tx_batch: Sender<Vec<u8>>,
    ) {
        tokio::spawn(async move {
            Self {
                committee,
                stake,
                rx_message,
                tx_batch,
            }
            .run()
            .await;
        });
    }

    /// Helper function. It waits for a future to complete and then delivers a value.
    async fn waiter(wait_for: CancelHandler, deliver: Stake) -> Stake {
        let _ = wait_for.await;
        deliver
    }

    async fn wait_for_quorum(
        committee: Committee,
        stake: Stake,
        batch: SerializedBatchMessage,
        handlers: Vec<(PublicKey, CancelHandler)>,
        tx_batch: Sender<SerializedBatchMessage>,
    ) {
        let mut wait_for_quorum: FuturesUnordered<_> = handlers
            .into_iter()
            .map(|(name, handler)| {
                let stake = committee.stake(&name);
                Self::waiter(handler, stake)
            })
            .collect();

        // Wait for the first 2f nodes to send back an Ack. Then we consider the batch
        // delivered and we send its digest to the primary (that will include it into
        // the dag). Each batch waits independently so a slow quorum does not block
        // newer batches from progressing through the worker pipeline.
        let mut total_stake = stake;
        while let Some(stake) = wait_for_quorum.next().await {
            total_stake += stake;
            if total_stake >= committee.quorum_threshold() {
                tx_batch
                    .send(batch)
                    .await
                    .expect("Failed to deliver batch");
                break;
            }
        }
    }

    /// Main loop.
    async fn run(&mut self) {
        while let Some(QuorumWaiterMessage { batch, handlers }) = self.rx_message.recv().await {
            let committee = self.committee.clone();
            let stake = self.stake;
            let tx_batch = self.tx_batch.clone();
            tokio::spawn(async move {
                Self::wait_for_quorum(committee, stake, batch, handlers, tx_batch).await;
            });
        }
    }
}
