use crate::common;
use quinn::{rustls, ClientConfig, Endpoint};
use std::io::{Error, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug)]
struct SkipVerify(Arc<quinn::rustls::crypto::CryptoProvider>);

impl SkipVerify {
    fn new(crypto_provider: Arc<rustls::crypto::CryptoProvider>) -> Self {
        Self(crypto_provider)
    }
}

impl quinn::rustls::client::danger::ServerCertVerifier for SkipVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &quinn::rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[quinn::rustls::pki_types::CertificateDer<'_>],
        _server_name: &quinn::rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: quinn::rustls::pki_types::UnixTime,
    ) -> std::result::Result<
        quinn::rustls::client::danger::ServerCertVerified,
        quinn::rustls::Error,
    > {
        Ok(quinn::rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &quinn::rustls::pki_types::CertificateDer<'_>,
        dss: &quinn::rustls::DigitallySignedStruct,
    ) -> std::result::Result<
        quinn::rustls::client::danger::HandshakeSignatureValid,
        quinn::rustls::Error,
    > {
        quinn::rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &quinn::rustls::pki_types::CertificateDer<'_>,
        dss: &quinn::rustls::DigitallySignedStruct,
    ) -> std::result::Result<
        quinn::rustls::client::danger::HandshakeSignatureValid,
        quinn::rustls::Error,
    > {
        quinn::rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<quinn::rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

pub async fn run(
    local: SocketAddr,
    remote: SocketAddr,
    sni: String,
    insecure: bool,
) -> std::io::Result<()> {
    let lis = TcpListener::bind(&local).await?;

    let crypto = if insecure {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipVerify::new(
                crypto_provider,
            )))
            .with_no_client_auth()
    } else {
        let root_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        rustls::ClientConfig::builder_with_provider(crypto_provider)
            .with_safe_default_protocol_versions()
            .map_err(common::to_invalid_input_error)?
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

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

    let (mut r_tcp, mut w_tcp) = tcp_stream.split();
    let (mut w_quic, mut r_quic) = connection.open_bi().await?;

    tokio::select! {
        _ = common::copy_tcp_to_quic(&mut r_tcp, &mut w_quic) => {},
        _ = common::copy_quic_to_tcp(&mut r_quic, &mut w_tcp) => {},
    };
    Ok(())
}
