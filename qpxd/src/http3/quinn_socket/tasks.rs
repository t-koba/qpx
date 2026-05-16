use super::broker::RemoteBrokerSocket;
use super::frame::{BrokerFrame, OwnedTransmit, decode_frame, encode_frame};
use super::routing::RouteState;
use anyhow::{Context, Result};
use std::io::ErrorKind;
use std::sync::{Arc, Mutex};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, Interest, ReadHalf, WriteHalf,
};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

pub(super) struct SendActual {
    pub(super) io: Arc<UdpSocket>,
    pub(super) inner: quinn::udp::UdpSocketState,
}

async fn send_actual(sender: &SendActual, transmit: &OwnedTransmit) -> std::io::Result<()> {
    loop {
        let borrowed = transmit.borrowed();
        match sender.io.try_io(Interest::WRITABLE, || {
            sender.inner.send((&*sender.io).into(), &borrowed)
        }) {
            Ok(result) => return Ok(result),
            Err(err) if err.kind() == ErrorKind::WouldBlock => sender.io.writable().await?,
            Err(err) => return Err(err),
        }
    }
}

pub(super) struct LocalBrokerView {
    pub(super) remote_writer: Arc<Mutex<Option<mpsc::UnboundedSender<BrokerFrame>>>>,
    pub(super) remote_route: Arc<Mutex<RouteState>>,
}

pub(super) async fn broker_writer_loop<S>(
    mut write_half: WriteHalf<S>,
    mut frames: mpsc::UnboundedReceiver<BrokerFrame>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    while let Some(frame) = frames.recv().await {
        if write_frame(&mut write_half, &frame).await.is_err() {
            break;
        }
    }
}

pub(super) async fn local_remote_reader_loop<S>(
    broker: LocalBrokerView,
    sender: Arc<SendActual>,
    mut read_half: ReadHalf<S>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let frame = match read_frame(&mut read_half).await {
            Ok(Some(frame)) => frame,
            Ok(None) | Err(_) => break,
        };
        match frame {
            BrokerFrame::OutboundTransmit(transmit) => {
                for packet in transmit.datagrams() {
                    broker
                        .remote_route
                        .lock()
                        .expect("remote route lock")
                        .observe_outbound(transmit.destination, packet);
                }
                let _ = send_actual(sender.as_ref(), &transmit).await;
            }
            BrokerFrame::InboundDatagram(_) => {}
        }
    }
    *broker.remote_writer.lock().expect("remote writer lock") = None;
    *broker.remote_route.lock().expect("remote route lock") = RouteState::default();
}

pub(super) async fn remote_broker_reader_loop<S>(
    socket: Arc<RemoteBrokerSocket>,
    mut read_half: ReadHalf<S>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        match read_frame(&mut read_half).await {
            Ok(Some(BrokerFrame::InboundDatagram(packet))) => {
                let _ = socket.recv_tx.send(packet);
            }
            Ok(Some(BrokerFrame::OutboundTransmit(_))) => {}
            Ok(None) | Err(_) => {
                socket.enter_direct_mode();
                break;
            }
        }
    }
}

async fn write_frame<W>(write_half: &mut W, frame: &BrokerFrame) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let encoded = encode_frame(frame)?;
    write_half
        .write_u32(encoded.len() as u32)
        .await
        .context("failed to write broker frame length")?;
    write_half
        .write_all(encoded.as_slice())
        .await
        .context("failed to write broker frame payload")?;
    write_half.flush().await.ok();
    Ok(())
}

async fn read_frame<R>(read_half: &mut R) -> Result<Option<BrokerFrame>>
where
    R: AsyncRead + Unpin,
{
    let len = match read_half.read_u32().await {
        Ok(len) => len as usize,
        Err(err) if err.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err).context("failed to read broker frame length"),
    };
    let mut buf = vec![0u8; len];
    read_half
        .read_exact(buf.as_mut_slice())
        .await
        .context("failed to read broker frame payload")?;
    decode_frame(buf.as_slice()).map(Some)
}
