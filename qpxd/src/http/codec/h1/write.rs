//! Shared HTTP/1 vectored-write helpers for response and upstream request paths.
//!
//! The response (`http::codec::h1::response`) and upstream request
//! (`upstream::raw_http1::request`) writers contained identical partial-write
//! loops, slice-advance routines, and chunk-size encoders; only the
//! `WriteZero` diagnostic text differed. This module keeps a single copy with
//! the message as a parameter so exact request/response errors are preserved.
use std::io::{Error as IoError, ErrorKind, IoSlice};
use tokio::io::{AsyncWrite, AsyncWriteExt};

/// Writes all slices with vectored I/O, advancing past partial writes.
///
/// `write_zero_message` preserves the caller-specific diagnostic:
/// callers pass `"failed to write HTTP/1 response"` or
/// `"failed to write HTTP/1 request"`.
pub(crate) async fn write_vectored_all<W>(
    writer: &mut W,
    slices: &[&[u8]],
    write_zero_message: &'static str,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut index = 0usize;
    let mut offset = 0usize;
    while index < slices.len() {
        while index < slices.len() && offset == slices[index].len() {
            index += 1;
            offset = 0;
        }
        if index >= slices.len() {
            return Ok(());
        }
        let mut io_slices = std::array::from_fn::<_, 4, _>(|_| IoSlice::new(&[]));
        let mut io_slice_count = 0usize;
        io_slices[io_slice_count] = IoSlice::new(&slices[index][offset..]);
        io_slice_count += 1;
        for slice in &slices[index + 1..] {
            if !slice.is_empty() {
                if io_slice_count == io_slices.len() {
                    break;
                }
                io_slices[io_slice_count] = IoSlice::new(slice);
                io_slice_count += 1;
            }
        }
        let written = writer.write_vectored(&io_slices[..io_slice_count]).await?;
        if written == 0 {
            return Err(IoError::new(ErrorKind::WriteZero, write_zero_message));
        }
        advance_slices(slices, &mut index, &mut offset, written);
    }
    Ok(())
}

fn advance_slices(slices: &[&[u8]], index: &mut usize, offset: &mut usize, written: usize) {
    let mut remaining = written;
    while remaining > 0 && *index < slices.len() {
        let available = slices[*index].len() - *offset;
        if remaining < available {
            *offset += remaining;
            return;
        }
        remaining -= available;
        *index += 1;
        *offset = 0;
    }
}

/// Encodes `len` as an uppercase-hex chunk-size line (`"<HEX>\r\n"`).
pub(crate) fn chunk_size_header(len: usize, out: &mut [u8; 18]) -> &[u8] {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut value = len;
    let mut cursor = 16;
    if value == 0 {
        cursor -= 1;
        out[cursor] = b'0';
    } else {
        while value > 0 {
            cursor -= 1;
            out[cursor] = HEX[value & 0x0f];
            value >>= 4;
        }
    }
    let digits = 16 - cursor;
    out.copy_within(cursor..16, 0);
    out[digits] = b'\r';
    out[digits + 1] = b'\n';
    &out[..digits + 2]
}

#[cfg(test)]
mod tests {
    use super::chunk_size_header;

    #[test]
    fn encodes_chunk_sizes_as_uppercase_hex_lines() {
        let mut out = [0_u8; 18];
        assert_eq!(chunk_size_header(0, &mut out), b"0\r\n");
        let mut out = [0_u8; 18];
        assert_eq!(chunk_size_header(255, &mut out), b"FF\r\n");
        let mut out = [0_u8; 18];
        assert_eq!(chunk_size_header(4096, &mut out), b"1000\r\n");
    }
}
