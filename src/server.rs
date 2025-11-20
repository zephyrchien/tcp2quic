use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpStream;

use quinn::{rustls, Endpoint, ServerConfig};

use crate::common;
use common::QuicStream;

pub async fn run(local: SocketAddr, remote: SocketAddr, hostname: String) {
    let (certs, key) = common::generate_certificate(vec![hostname]).unwrap();

    let rustls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();

    let mut server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)
            .unwrap(),
    ));

    server_config.transport = Arc::new(common::transport_config());

    let endpoint = Endpoint::server(server_config, local).unwrap();

    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(handle(incoming, remote));
    }
}

async fn handle(
    incoming: quinn::Incoming,
    remote: SocketAddr,
) -> std::io::Result<()> {
    let connecting = incoming.accept().map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::ConnectionAborted, e)
    })?;

    let connection = match connecting.into_0rtt() {
        Ok((conn, _)) => conn,
        Err(conn) => conn.await.map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::ConnectionAborted, e)
        })?,
    };

    loop {
        match connection.accept_bi().await {
            Ok((send, recv)) => {
                let mut quic_stream = QuicStream::new(send, recv);
                let mut tcp_stream = TcpStream::connect(&remote).await?;
                tcp_stream.set_nodelay(true)?;
                let _ = tokio::io::copy_bidirectional(
                    &mut quic_stream,
                    &mut tcp_stream,
                )
                .await;
            }
            _ => {
                break;
            }
        }
    }

    Ok(())
}
