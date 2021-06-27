use crate::common;
use futures::{future::FutureExt, select};
use quinn::{ClientConfigBuilder, Endpoint};
use std::io::{Error, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};

struct SkipVerify;

impl rustls::ServerCertVerifier for SkipVerify {
    fn verify_server_cert(
        &self,
        _: &rustls::RootCertStore,
        _: &[rustls::Certificate],
        _: webpki::DNSNameRef<'_>,
        _: &[u8],
    ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
        Ok(rustls::ServerCertVerified::assertion())
    }
}

pub async fn run(
    local: SocketAddr,
    remote: SocketAddr,
    sni: String,
) -> std::io::Result<()> {
    let lis = TcpListener::bind(&local).await?;
    loop {
        let (stream, _) = lis.accept().await?;
        stream.set_nodelay(true)?;
        tokio::spawn(handle(stream, remote, sni.clone()));
    }
}

async fn handle(
    mut tcp_stream: TcpStream,
    remote: SocketAddr,
    sni: String,
) -> std::io::Result<()> {
    let mut config = ClientConfigBuilder::default().build();
    let tls_config = Arc::get_mut(&mut config.crypto).unwrap();
    tls_config
        .dangerous()
        .set_certificate_verifier(Arc::new(SkipVerify));

    let mut ep_builder = Endpoint::builder();
    ep_builder.default_client_config(config);
    let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
    let (ep, _) = ep_builder.bind(&local).unwrap();
    let quic_conn = ep
        .connect(&remote, &sni)
        .map_err(|e| Error::new(ErrorKind::ConnectionAborted, e))?
        .await?;

    let (mut r_tcp, mut w_tcp) = tcp_stream.split();
    let (mut w_udp, mut r_udp) = quic_conn.connection.open_bi().await?;
    select! {
        _ = common::copy(&mut r_tcp, &mut w_udp).fuse() => (),
        _ = common::copy(&mut r_udp, &mut w_tcp).fuse() => (),
    };
    Ok(())
}
