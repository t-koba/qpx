//! Stop-safe `h3::quic` adapter over Quinn.
//!
//! Released h3-quinn 0.0.10 moves the Quinn receive stream into a reusable
//! boxed read future. While that future is pending `stop_sending` panics on
//! `Option::unwrap(None)` (hyperium/h3#330, #361), and no public Quinn handle
//! can stop the stream on its behalf. qpx owns this thin adapter until an
//! upstream release applies STOP_SENDING immediately after a pending read.

use bytes::{Buf, Bytes};
use futures_util::{Stream, StreamExt, stream};
use h3::{
    error::Code,
    quic::{self, ConnectionErrorIncoming, StreamErrorIncoming, StreamId, WriteBuf},
};
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

type BoxStreamSync<'a, T> = Pin<Box<dyn Stream<Item = T> + Sync + Send + 'a>>;
type BiResult = Result<(quinn::SendStream, quinn::RecvStream), quinn::ConnectionError>;
type UniResult = Result<quinn::SendStream, quinn::ConnectionError>;
type RecvResult = Result<quinn::RecvStream, quinn::ConnectionError>;

pub(crate) struct Connection {
    conn: quinn::Connection,
    incoming_bi: BoxStreamSync<'static, BiResult>,
    incoming_uni: BoxStreamSync<'static, RecvResult>,
    opening_bi: Option<BoxStreamSync<'static, BiResult>>,
    opening_uni: Option<BoxStreamSync<'static, UniResult>>,
}

impl Connection {
    pub(crate) fn new(conn: quinn::Connection) -> Self {
        Self {
            incoming_bi: Box::pin(stream::unfold(conn.clone(), |conn| async {
                Some((conn.accept_bi().await, conn))
            })),
            incoming_uni: Box::pin(stream::unfold(conn.clone(), |conn| async {
                Some((conn.accept_uni().await, conn))
            })),
            conn,
            opening_bi: None,
            opening_uni: None,
        }
    }

    fn open_streams(&self) -> OpenStreams {
        OpenStreams {
            conn: self.conn.clone(),
            opening_bi: None,
            opening_uni: None,
        }
    }
}

impl<B: Buf> quic::Connection<B> for Connection {
    type RecvStream = RecvStream;
    type OpenStreams = OpenStreams;

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
        let (send, recv) = ready!(self.incoming_bi.poll_next_unpin(cx))
            .expect("incoming_bi stream never ends")
            .map_err(convert_connection_error)?;
        Poll::Ready(Ok(BidiStream {
            send: SendStream::new(send),
            recv: RecvStream::new(recv),
        }))
    }

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
        let recv = ready!(self.incoming_uni.poll_next_unpin(cx))
            .expect("incoming_uni stream never ends")
            .map_err(convert_connection_error)?;
        Poll::Ready(Ok(RecvStream::new(recv)))
    }

    fn opener(&self) -> Self::OpenStreams {
        self.open_streams()
    }
}

impl<B: Buf> quic::OpenStreams<B> for Connection {
    type BidiStream = BidiStream<B>;
    type SendStream = SendStream<B>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        poll_open_bidi(&self.conn, &mut self.opening_bi, cx)
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        poll_open_send(&self.conn, &mut self.opening_uni, cx)
    }

    fn close(&mut self, code: Code, reason: &[u8]) {
        self.conn.close(
            quinn::VarInt::from_u64(code.value()).expect("invalid error code"),
            reason,
        );
    }
}

impl<B: Buf> h3_datagram::quic_traits::DatagramConnectionExt<B> for Connection {
    type SendDatagramHandler = h3_quinn::datagram::SendDatagramHandler;
    type RecvDatagramHandler = h3_quinn::datagram::RecvDatagramHandler;

    fn send_datagram_handler(&self) -> Self::SendDatagramHandler {
        <h3_quinn::Connection as h3_datagram::quic_traits::DatagramConnectionExt<B>>::send_datagram_handler(
            &h3_quinn::Connection::new(self.conn.clone()),
        )
    }

    fn recv_datagram_handler(&self) -> Self::RecvDatagramHandler {
        <h3_quinn::Connection as h3_datagram::quic_traits::DatagramConnectionExt<B>>::recv_datagram_handler(
            &h3_quinn::Connection::new(self.conn.clone()),
        )
    }
}

pub(crate) struct OpenStreams {
    conn: quinn::Connection,
    opening_bi: Option<BoxStreamSync<'static, BiResult>>,
    opening_uni: Option<BoxStreamSync<'static, UniResult>>,
}

impl Clone for OpenStreams {
    fn clone(&self) -> Self {
        Self {
            conn: self.conn.clone(),
            opening_bi: None,
            opening_uni: None,
        }
    }
}

impl<B: Buf> quic::OpenStreams<B> for OpenStreams {
    type BidiStream = BidiStream<B>;
    type SendStream = SendStream<B>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        poll_open_bidi(&self.conn, &mut self.opening_bi, cx)
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        poll_open_send(&self.conn, &mut self.opening_uni, cx)
    }

    fn close(&mut self, code: Code, reason: &[u8]) {
        self.conn.close(
            quinn::VarInt::from_u64(code.value()).expect("invalid error code"),
            reason,
        );
    }
}

fn poll_open_bidi<B: Buf>(
    conn: &quinn::Connection,
    opening: &mut Option<BoxStreamSync<'static, BiResult>>,
    cx: &mut Context<'_>,
) -> Poll<Result<BidiStream<B>, StreamErrorIncoming>> {
    let opening = opening.get_or_insert_with(|| {
        Box::pin(stream::unfold(conn.clone(), |conn| async {
            Some((conn.open_bi().await, conn))
        }))
    });
    let (send, recv) = ready!(opening.poll_next_unpin(cx))
        .expect("opening_bi stream never ends")
        .map_err(|e| stream_connection_error(convert_connection_error(e)))?;
    Poll::Ready(Ok(BidiStream {
        send: SendStream::new(send),
        recv: RecvStream::new(recv),
    }))
}

fn poll_open_send<B: Buf>(
    conn: &quinn::Connection,
    opening: &mut Option<BoxStreamSync<'static, UniResult>>,
    cx: &mut Context<'_>,
) -> Poll<Result<SendStream<B>, StreamErrorIncoming>> {
    let opening = opening.get_or_insert_with(|| {
        Box::pin(stream::unfold(conn.clone(), |conn| async {
            Some((conn.open_uni().await, conn))
        }))
    });
    let send = ready!(opening.poll_next_unpin(cx))
        .expect("opening_uni stream never ends")
        .map_err(|e| stream_connection_error(convert_connection_error(e)))?;
    Poll::Ready(Ok(SendStream::new(send)))
}

pub(crate) struct BidiStream<B: Buf> {
    send: SendStream<B>,
    recv: RecvStream,
}

impl<B: Buf> quic::BidiStream<B> for BidiStream<B> {
    type SendStream = SendStream<B>;
    type RecvStream = RecvStream;

    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        (self.send, self.recv)
    }
}

impl<B: Buf> quic::RecvStream for BidiStream<B> {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
        quic::RecvStream::poll_data(&mut self.recv, cx)
    }

    fn stop_sending(&mut self, error_code: u64) {
        quic::RecvStream::stop_sending(&mut self.recv, error_code);
    }

    fn recv_id(&self) -> StreamId {
        quic::RecvStream::recv_id(&self.recv)
    }
}

impl<B: Buf> quic::SendStream<B> for BidiStream<B> {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        quic::SendStream::poll_ready(&mut self.send, cx)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        quic::SendStream::poll_finish(&mut self.send, cx)
    }

    fn reset(&mut self, reset_code: u64) {
        quic::SendStream::reset(&mut self.send, reset_code);
    }

    fn send_data<D: Into<WriteBuf<B>>>(&mut self, data: D) -> Result<(), StreamErrorIncoming> {
        quic::SendStream::send_data(&mut self.send, data)
    }

    fn send_id(&self) -> StreamId {
        quic::SendStream::send_id(&self.send)
    }
}

impl<B: Buf> quic::SendStreamUnframed<B> for BidiStream<B> {
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut D,
    ) -> Poll<Result<usize, StreamErrorIncoming>> {
        quic::SendStreamUnframed::poll_send(&mut self.send, cx, buf)
    }
}

pub(crate) struct RecvStream {
    stream: quinn::RecvStream,
}

impl RecvStream {
    fn new(stream: quinn::RecvStream) -> Self {
        Self { stream }
    }
}

impl quic::RecvStream for RecvStream {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
        // Quinn's read_chunk is cancellation-safe: dropping this borrowed
        // future on Pending leaves the stream owned by us and keeps its waker
        // registered. stop_sending can therefore apply the exact code even
        // while a read is outstanding.
        let read = self.stream.read_chunk(usize::MAX, true);
        let read = std::pin::pin!(read);
        let chunk = ready!(read.poll(cx));
        Poll::Ready(Ok(chunk
            .map_err(convert_read_error)?
            .map(|chunk| chunk.bytes)))
    }

    fn stop_sending(&mut self, error_code: u64) {
        let code = quinn::VarInt::from_u64(error_code).expect("invalid error code");
        let _ = self.stream.stop(code);
    }

    fn recv_id(&self) -> StreamId {
        let num: u64 = self.stream.id().into();
        num.try_into().expect("invalid stream id")
    }
}

pub(crate) struct SendStream<B: Buf> {
    stream: quinn::SendStream,
    writing: Option<WriteBuf<B>>,
}

impl<B: Buf> SendStream<B> {
    fn new(stream: quinn::SendStream) -> Self {
        Self {
            stream,
            writing: None,
        }
    }
}

impl<B: Buf> quic::SendStream<B> for SendStream<B> {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        if let Some(data) = self.writing.as_mut() {
            while data.has_remaining() {
                let written = ready!(Pin::new(&mut self.stream).poll_write(cx, data.chunk()))
                    .map_err(convert_write_error)?;
                data.advance(written);
            }
        }
        self.writing = None;
        Poll::Ready(Ok(()))
    }

    fn poll_finish(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        Poll::Ready(
            self.stream
                .finish()
                .map_err(|e| StreamErrorIncoming::Unknown(Box::new(e))),
        )
    }

    fn reset(&mut self, reset_code: u64) {
        let _ = self
            .stream
            .reset(quinn::VarInt::from_u64(reset_code).unwrap_or(quinn::VarInt::MAX));
    }

    fn send_data<D: Into<WriteBuf<B>>>(&mut self, data: D) -> Result<(), StreamErrorIncoming> {
        if self.writing.is_some() {
            return Err(stream_connection_error(
                ConnectionErrorIncoming::InternalError(
                    "send_data called before send stream was ready".to_string(),
                ),
            ));
        }
        self.writing = Some(data.into());
        Ok(())
    }

    fn send_id(&self) -> StreamId {
        let num: u64 = self.stream.id().into();
        num.try_into().expect("invalid stream id")
    }
}

impl<B: Buf> quic::SendStreamUnframed<B> for SendStream<B> {
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut D,
    ) -> Poll<Result<usize, StreamErrorIncoming>> {
        if self.writing.is_some() {
            panic!("poll_send called before send stream was ready");
        }
        let written = ready!(Pin::new(&mut self.stream).poll_write(cx, buf.chunk()))
            .map_err(convert_write_error)?;
        buf.advance(written);
        Poll::Ready(Ok(written))
    }
}

fn stream_connection_error(error: ConnectionErrorIncoming) -> StreamErrorIncoming {
    StreamErrorIncoming::ConnectionErrorIncoming {
        connection_error: error,
    }
}

fn convert_connection_error(error: quinn::ConnectionError) -> ConnectionErrorIncoming {
    match error {
        quinn::ConnectionError::ApplicationClosed(application_close) => {
            ConnectionErrorIncoming::ApplicationClose {
                error_code: application_close.error_code.into(),
            }
        }
        quinn::ConnectionError::TimedOut => ConnectionErrorIncoming::Timeout,
        error @ quinn::ConnectionError::VersionMismatch
        | error @ quinn::ConnectionError::Reset
        | error @ quinn::ConnectionError::LocallyClosed
        | error @ quinn::ConnectionError::CidsExhausted
        | error @ quinn::ConnectionError::TransportError(_)
        | error @ quinn::ConnectionError::ConnectionClosed(_) => {
            ConnectionErrorIncoming::Undefined(Arc::new(error))
        }
    }
}

fn convert_read_error(error: quinn::ReadError) -> StreamErrorIncoming {
    match error {
        quinn::ReadError::Reset(code) => StreamErrorIncoming::StreamTerminated {
            error_code: code.into_inner(),
        },
        quinn::ReadError::ConnectionLost(error) => {
            stream_connection_error(convert_connection_error(error))
        }
        error @ quinn::ReadError::ClosedStream | error @ quinn::ReadError::ZeroRttRejected => {
            StreamErrorIncoming::Unknown(Box::new(error))
        }
        quinn::ReadError::IllegalOrderedRead => {
            panic!("qpx h3 adapter only performs ordered reads")
        }
    }
}

fn convert_write_error(error: quinn::WriteError) -> StreamErrorIncoming {
    match error {
        quinn::WriteError::Stopped(code) => StreamErrorIncoming::StreamTerminated {
            error_code: code.into_inner(),
        },
        quinn::WriteError::ConnectionLost(error) => {
            stream_connection_error(convert_connection_error(error))
        }
        error @ quinn::WriteError::ClosedStream | error @ quinn::WriteError::ZeroRttRejected => {
            StreamErrorIncoming::Unknown(Box::new(error))
        }
    }
}
