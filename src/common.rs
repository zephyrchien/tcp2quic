use quinn::rustls;
use std::io::Result;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{timeout, Duration};

const BUFFER_SIZE: usize = 8 * 1024;
const FLUSH_TIMEOUT_MS: u64 = 1;

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

pub fn create_transport_config() -> Result<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();

    transport.max_concurrent_bidi_streams(100u32.into());
    transport.max_concurrent_uni_streams(100u32.into());
    transport.max_idle_timeout(Some(
        std::time::Duration::from_millis(120000)
            .try_into()
            .map_err(to_invalid_input_error)?,
    ));

    transport.stream_receive_window(
        quinn::VarInt::from_u64(4 * 1024 * 1024).unwrap_or(quinn::VarInt::MAX),
    );
    transport.receive_window(
        quinn::VarInt::from_u64(64 * 1024 * 1024).unwrap_or(quinn::VarInt::MAX),
    );
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

    Ok(transport)
}

// Only flush when a read operation is blocked
pub async fn copy_quic_to_tcp(
    recv_stream: &mut quinn::RecvStream,
    tcp_writer: &mut (impl AsyncWrite + Unpin),
) -> Result<()> {
    let mut buf = vec![0u8; BUFFER_SIZE];
    let mut need_flush = false;

    loop {
        let read_result =
            timeout(Duration::from_millis(FLUSH_TIMEOUT_MS), async {
                recv_stream.read(&mut buf).await
            })
            .await;

        match read_result {
            Ok(Ok(Some(n))) if n > 0 => {
                tcp_writer.write_all(&buf[..n]).await?;
                need_flush = true;
            }
            Ok(Ok(_)) => break,
            Ok(Err(e)) => return Err(std::io::Error::other(e)),
            Err(_) => {
                if need_flush {
                    tcp_writer.flush().await?;
                    need_flush = false;
                }
                continue;
            }
        }
    }

    if need_flush {
        tcp_writer.flush().await?;
    }
    tcp_writer.shutdown().await?;
    Ok(())
}

pub async fn copy_tcp_to_quic(
    tcp_reader: &mut (impl AsyncRead + Unpin),
    send_stream: &mut quinn::SendStream,
) -> Result<()> {
    let mut buf = vec![0u8; BUFFER_SIZE];
    let mut need_flush = false;

    loop {
        let read_result =
            timeout(Duration::from_millis(FLUSH_TIMEOUT_MS), async {
                tcp_reader.read(&mut buf).await
            })
            .await;

        match read_result {
            Ok(Ok(n)) if n > 0 => {
                send_stream.write_all(&buf[..n]).await?;
                need_flush = true;
            }
            Ok(Ok(_)) => break,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                if need_flush {
                    send_stream.flush().await?;
                    need_flush = false;
                }
                continue;
            }
        }
    }

    if need_flush {
        send_stream.flush().await?;
    }
    send_stream.finish()?;
    Ok(())
}
