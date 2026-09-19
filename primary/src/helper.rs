// Copyright(C) Facebook, Inc. and its affiliates.
use crate::primary::PrimaryMessage;
use bytes::Bytes;
use config::Committee;
use crypto::{Digest, PublicKey};
use log::{error, warn};
use network::SimpleSender;
use std::time::{Duration, Instant};
use store::Store;
use tokio::sync::mpsc::Receiver;

/// A task dedicated to help other authorities by replying to their certificates requests.
pub struct Helper {
    /// The public key of this primary.
    name: PublicKey,
    /// The committee information.
    committee: Committee,
    /// The persistent storage.
    store: Store,
    /// Input channel to receive certificates requests.
    rx_primaries: Receiver<(Vec<Digest>, PublicKey)>,
    /// A network sender to reply to the sync requests.
    network: SimpleSender,
    /// Node-local attack clock.
    boot_instant: Instant,
}

impl Helper {
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        store: Store,
        rx_primaries: Receiver<(Vec<Digest>, PublicKey)>,
    ) {
        tokio::spawn(async move {
            Self {
                name,
                committee,
                store,
                rx_primaries,
                network: SimpleSender::new(),
                boot_instant: Instant::now(),
            }
            .run()
            .await;
        });
    }

    fn attack_active(&self) -> bool {
        if !self.committee.attack_enabled || !self.committee.attack_limit_certificates {
            return false;
        }
        let elapsed = self.boot_instant.elapsed();
        let start = Duration::from_secs(self.committee.attack_start_secs);
        if elapsed < start {
            return false;
        }
        let duration_secs = self.committee.attack_duration_secs;
        if duration_secs == 0 {
            return true;
        }
        elapsed < start + Duration::from_secs(duration_secs)
    }

    async fn run(&mut self) {
        while let Some((digests, origin)) = self.rx_primaries.recv().await {
            // TODO [issue #195]: Do some accounting to prevent bad nodes from monopolizing our resources.

            // get the requestors address.
            let address = match self.committee.primary(&origin) {
                Ok(x) => x.primary_to_primary,
                Err(e) => {
                    warn!("Unexpected certificate request: {}", e);
                    continue;
                }
            };

            let delay_ms = if self.attack_active() {
                self.committee.attack_link_delay_at_epoch_ms(
                    &self.name,
                    &origin,
                    self.committee.attack_group_epoch(self.boot_instant.elapsed()),
                )
            } else {
                0
            };

            // Reply to the request (the best we can).
            for digest in digests {
                match self.store.read(digest.to_vec()).await {
                    Ok(Some(data)) => {
                        // TODO: Remove this deserialization-serialization in the critical path.
                        let certificate = bincode::deserialize(&data)
                            .expect("Failed to deserialize our own certificate");
                        let bytes = bincode::serialize(&PrimaryMessage::Certificate(certificate))
                            .expect("Failed to serialize our own certificate");
                        self.network
                            .send_delayed(
                                address,
                                Bytes::from(bytes),
                                Duration::from_millis(delay_ms),
                            )
                            .await;
                    }
                    Ok(None) => (),
                    Err(e) => error!("{}", e),
                }
            }
        }
    }
}
