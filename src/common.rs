use quinn::{Certificate, PrivateKey};
use std::io::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub fn generate_certificate(
    san: Vec<String>,
) -> Result<(Certificate, PrivateKey)> {
    let certificate = rcgen::generate_simple_self_signed(san).unwrap();
    let cert = certificate.serialize_der().unwrap();
    let key = certificate.serialize_private_key_der();
    let cert = Certificate::from_der(&cert).unwrap();
    let key = PrivateKey::from_der(&key).unwrap();
    Ok((cert, key))
}

pub async fn copy<R, W>(mut r: R, mut w: W) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 1024];
    let mut n;
    loop {
        n = r.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        w.write(&buf[..n]).await?;
        w.flush().await?;
    }
    w.shutdown().await?;
    Ok(())
}
