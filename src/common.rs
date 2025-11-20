use std::io::{Error, Result};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use quinn::{rustls, RecvStream, SendStream};

pub struct QuicStream {
    send: SendStream,
    recv: RecvStream,
}

impl QuicStream {
    pub fn new(send: SendStream, recv: RecvStream) -> Self {
        Self { send, recv }
    }
}

impl From<(SendStream, RecvStream)> for QuicStream {
    fn from(value: (SendStream, RecvStream)) -> Self {
        Self::new(value.0, value.1)
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        Pin::new(&mut self.recv)
            .poll_read_buf(cx, buf)
            .map_err(Error::other)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        Pin::new(&mut self.send)
            .poll_write(cx, buf)
            .map_err(Error::other)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<()>> {
        Pin::new(&mut self.send)
            .poll_flush(cx)
            .map_err(Error::other)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<()>> {
        Pin::new(&mut self.send)
            .poll_shutdown(cx)
            .map_err(Error::other)
    }
}

pub fn to_invalid_input_error<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string())
}

pub fn generate_certificate(
    san: Vec<String>,
) -> Result<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    let rcgen::CertifiedKey {
        cert,
        signing_key: key,
    } = rcgen::generate_simple_self_signed(san)
        .map_err(std::io::Error::other)?;

    let cert_der = cert.der().to_owned();
    let key_der =
        rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der())
            .map_err(std::io::Error::other)?;

    Ok((vec![cert_der], key_der))
}

pub fn transport_config() -> quinn::TransportConfig {
    use quinn::VarInt;
    let mut transport = quinn::TransportConfig::default();

    transport.max_concurrent_bidi_streams(100u32.into());
    transport.max_concurrent_uni_streams(100u32.into());
    transport.max_idle_timeout(Some(VarInt::from_u32(120_000).into()));

    transport.stream_receive_window(VarInt::from_u32(4 * 1024 * 1024));
    transport.receive_window(VarInt::from_u32(64 * 1024 * 1024));
    transport.send_window(64 * 1024 * 1024);

    transport.initial_mtu(1350);
    transport.enable_segmentation_offload(true);
    transport.mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()));

    transport.congestion_controller_factory(Arc::new(
        quinn::congestion::BbrConfig::default(),
    ));

    transport.keep_alive_interval(Some(std::time::Duration::from_secs(15)));
    transport.datagram_receive_buffer_size(Some(64 * 1024));
    transport.datagram_send_buffer_size(64 * 1024);

    transport
}
