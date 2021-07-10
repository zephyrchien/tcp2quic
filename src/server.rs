use crate::common;
use futures::{future::FutureExt, select, StreamExt};
use quinn::{
    CertificateChain, Connecting, Endpoint, NewConnection, ServerConfigBuilder,
};
use std::net::SocketAddr;
use tokio::net::TcpStream;

pub async fn run(local: SocketAddr, remote: SocketAddr, hostname: String) {
    let (cert, key) = common::generate_certificate(vec![hostname]).unwrap();
    let mut config_builder = ServerConfigBuilder::default();
    config_builder
        .certificate(CertificateChain::from_certs(vec![cert]), key)
        .unwrap();
    let config = config_builder.build();
    let mut ep_builder = Endpoint::builder();
    ep_builder.listen(config);
    let (_, mut incoming) = ep_builder.bind(&local).expect("failed to bind");
    while let Some(conn) = incoming.next().await {
        tokio::spawn(handle(conn, remote));
    }
}

async fn handle(
    connecting: Connecting,
    remote: SocketAddr,
) -> std::io::Result<()> {
    let connection = match connecting.into_0rtt() {
        Ok((conn, _)) => conn,
        Err(conn) => conn.await?,
    };
    let NewConnection {
        connection: _,
        mut bi_streams,
        ..
    } = connection;

    let mut tcp_stream = TcpStream::connect(&remote).await?;
    tcp_stream.set_nodelay(true)?;
    let (mut r_tcp, mut w_tcp) = tcp_stream.split();
    while let Some(udp_stream) = bi_streams.next().await {
        let (mut w_udp, mut r_udp) = udp_stream?;
        select! {
            _ = common::copy(&mut r_udp, &mut w_tcp).fuse() => {},
            _ = common::copy(&mut r_tcp, &mut w_udp).fuse() => {},
        };
    }
    Ok(())
}
