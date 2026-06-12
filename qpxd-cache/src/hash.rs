use sha2::Digest as _;

pub fn sha256_hex(input: &[u8]) -> String {
    let digest = sha2::Sha256::digest(input);
    hex_lower(digest.as_slice())
}

fn hex_lower(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0f) as usize] as char);
    }
    out
}
