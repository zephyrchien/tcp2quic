use crate::common;
use quinn::{rustls, Endpoint, ServerConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;

pub async fn run(
    local: SocketAddr,
    remote: SocketAddr,
    hostname: String,
) -> std::io::Result<()> {
    let (certs, key) = common::generate_certificate(vec![hostname])?;

    let rustls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(common::to_invalid_input_error)?;

    let mut server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)
            .map_err(std::io::Error::other)?,
    ));

    let transport_config = common::create_transport_config()?;
    server_config.transport = Arc::new(transport_config);

    let endpoint = Endpoint::server(server_config, local)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::AddrInUse, e))?;

    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(handle(incoming, remote));
    }

    Ok(())
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
            Ok((mut w_quic, mut r_quic)) => {
                let mut tcp_stream = TcpStream::connect(&remote).await?;
                tcp_stream.set_nodelay(true)?;
                let (mut r_tcp, mut w_tcp) = tcp_stream.split();

                tokio::select! {
                    _ = common::copy_quic_to_tcp(&mut r_quic, &mut w_tcp) => {},
                    _ = common::copy_tcp_to_quic(&mut r_tcp, &mut w_quic) => {},
                };
            }
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                break;
            }
            Err(quinn::ConnectionError::ConnectionClosed { .. }) => {
                break;
            }
            Err(_) => {
                break;
            }
        }
    }

    Ok(())
}
