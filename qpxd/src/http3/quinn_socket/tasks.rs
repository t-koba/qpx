mod io;

use super::broker::RemoteBrokerSocket;
use super::frame::{BrokerFrame, OwnedTransmit};
use super::routing::SharedRouteState;
use arc_swap::ArcSwapOption;
use io::{read_frame, write_frame_no_flush};
use std::io::ErrorKind;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, Interest, ReadHalf, WriteHalf};
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
    pub(super) remote_writer: Arc<ArcSwapOption<mpsc::Sender<BrokerFrame>>>,
    pub(super) remote_route: Arc<SharedRouteState>,
}

pub(super) async fn broker_writer_loop<S>(
    mut write_half: WriteHalf<S>,
    mut frames: mpsc::Receiver<BrokerFrame>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    while let Some(frame) = frames.recv().await {
        if write_frame_no_flush(&mut write_half, &frame).await.is_err() {
            break;
        }
        while let Ok(frame) = frames.try_recv() {
            if write_frame_no_flush(&mut write_half, &frame).await.is_err() {
                return;
            }
        }
        if write_half.flush().await.is_err() {
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
                    if broker
                        .remote_route
                        .outbound_update_needed(transmit.destination, packet)
                    {
                        broker
                            .remote_route
                            .observe_outbound(transmit.destination, packet);
                    }
                }
                let _ = send_actual(sender.as_ref(), &transmit).await;
            }
            BrokerFrame::InboundDatagram(_) => {}
        }
    }
    broker.remote_writer.store(None);
    broker.remote_route.reset();
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
                socket.enqueue_injected_packet(packet, "broker_stream");
            }
            Ok(Some(BrokerFrame::OutboundTransmit(_))) => {}
            Ok(None) | Err(_) => {
                socket.enter_direct_mode();
                break;
            }
        }
    }
}
