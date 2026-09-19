// Copyright(C) Facebook, Inc. and its affiliates.
use super::*;
use crate::common::listener;
use futures::future::try_join_all;

#[tokio::test]
async fn simple_send() {
    // Run a TCP server.
    let address = "127.0.0.1:6100".parse::<SocketAddr>().unwrap();
    let message = "Hello, world!";
    let handle = listener(address, message.to_string());

    // Make the network sender and send the message.
    let mut sender = SimpleSender::new();
    sender.send(address, Bytes::from(message)).await;

    // Ensure the server received the message (ie. it did not panic).
    assert!(handle.await.is_ok());
}

#[tokio::test]
async fn broadcast() {
    // Run 3 TCP servers.
    let message = "Hello, world!";
    let (handles, addresses): (Vec<_>, Vec<_>) = (0..3)
        .map(|x| {
            let address = format!("127.0.0.1:{}", 6_200 + x)
                .parse::<SocketAddr>()
                .unwrap();
            (listener(address, message.to_string()), address)
        })
        .collect::<Vec<_>>()
        .into_iter()
        .unzip();

    // Make the network sender and send the message.
    let mut sender = SimpleSender::new();
    sender.broadcast(addresses, Bytes::from(message)).await;

    // Ensure all servers received the broadcast.
    assert!(try_join_all(handles).await.is_ok());
}

#[tokio::test]
async fn delayed_reply_does_not_block_immediate_reply() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut framed = Framed::new(stream, LengthDelimitedCodec::new());
        assert_eq!(framed.next().await.unwrap().unwrap().as_ref(), b"immediate");
        assert_eq!(framed.next().await.unwrap().unwrap().as_ref(), b"delayed");
    });
    let mut sender = SimpleSender::new();
    let started = tokio::time::Instant::now();
    sender
        .send_delayed(
            address,
            Bytes::from_static(b"delayed"),
            std::time::Duration::from_millis(200),
        )
        .await;
    sender.send(address, Bytes::from_static(b"immediate")).await;
    tokio::time::timeout(std::time::Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
    assert!(started.elapsed() >= std::time::Duration::from_millis(200));
}
