use std::io::{Error, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};

use quinn::{rustls, ClientConfig, Endpoint};

use crate::common;
use common::QuicStream;

mod verify {
    use super::rustls;
    use rustls::client::danger;
    use rustls::pki_types;

    #[derive(Debug)]
    pub struct SkipVerify;

    impl danger::ServerCertVerifier for SkipVerify {
        fn verify_server_cert(
            &self,
            _: &pki_types::CertificateDer<'_>,
            _: &[pki_types::CertificateDer<'_>],
            _: &pki_types::ServerName<'_>,
            _: &[u8],
            _: pki_types::UnixTime,
        ) -> Result<danger::ServerCertVerified, rustls::Error> {
            Ok(danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<danger::HandshakeSignatureValid, rustls::Error> {
            Ok(danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<danger::HandshakeSignatureValid, rustls::Error> {
            Ok(danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            use rustls::SignatureScheme;
            vec![
                SignatureScheme::RSA_PKCS1_SHA1,
                SignatureScheme::ECDSA_SHA1_Legacy,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
                SignatureScheme::ED448,
            ]
        }
    }
}

pub async fn run(
    local: SocketAddr,
    remote: SocketAddr,
    sni: String,
) -> std::io::Result<()> {
    let lis = TcpListener::bind(&local).await?;

    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verify::SkipVerify {}))
        .with_no_client_auth();

    let mut quic_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .map_err(Error::other)?,
    ));

    let transport = common::create_transport_config()?;
    quic_config.transport_config(Arc::new(transport));

    let local_bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
    let mut ep = Endpoint::client(local_bind)?;
    ep.set_default_client_config(quic_config);

    while let Ok((stream, _)) = lis.accept().await {
        if let Err(e) = stream.set_nodelay(true) {
            eprintln!("Failed to set TCP_NODELAY: {}", e);
            continue;
        }
        tokio::spawn(handle(stream, ep.clone(), remote, sni.clone()));
    }

    Ok(())
}

async fn handle(
    mut tcp_stream: TcpStream,
    ep: Endpoint,
    remote: SocketAddr,
    sni: String,
) -> std::io::Result<()> {
    let connecting = ep
        .connect(remote, &sni)
        .map_err(|e| Error::new(ErrorKind::ConnectionAborted, e))?;
    let connection = match connecting.into_0rtt() {
        Ok((conn, zero)) => {
            zero.await;
            conn
        }
        Err(conn) => conn.await?,
    };

    let mut quic_stream: QuicStream = connection.open_bi().await?.into();

    tokio::io::copy_bidirectional(&mut tcp_stream, &mut quic_stream)
        .await
        .map(|_| ())
}
