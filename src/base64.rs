//! Base64 (RFC 4648, standard alphabet): decoding keys, encoding their
//! fingerprints.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// `text` decoded, padded or not; `None` when it isn't base64.
pub(crate) fn decode(text: &str) -> Option<Vec<u8>> {
    let digits = text.strip_suffix("==").or_else(|| text.strip_suffix('='));
    let digits = digits.unwrap_or(text).as_bytes();
    if digits.len() % 4 == 1 {
        return None;
    }
    let mut bytes = Vec::with_capacity(digits.len() / 4 * 3 + 2);
    for group in digits.chunks(4) {
        let mut bits = 0u32;
        for &digit in group {
            bits = bits << 6 | value(digit)?;
        }
        // The group's 6-bit digits, left-aligned in 24 bits.
        bits <<= 6 * (4 - group.len());
        let [_, high, middle, low] = bits.to_be_bytes();
        bytes.extend(&[high, middle, low][..group.len() - 1]);
    }
    Some(bytes)
}

/// `bytes` encoded without `=` padding, as OpenSSH prints fingerprints.
pub(crate) fn encode_unpadded(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut group = [0u8; 3];
        group[..chunk.len()].copy_from_slice(chunk);
        let bits = u32::from_be_bytes([0, group[0], group[1], group[2]]);
        for index in 0..=chunk.len() {
            let digit = (bits >> (18 - 6 * index)) & 0x3f;
            text.push(char::from(ALPHABET[digit as usize]));
        }
    }
    text
}

fn value(digit: u8) -> Option<u32> {
    ALPHABET
        .iter()
        .position(|&d| d == digit)
        .map(|position| position as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_4648_vectors() {
        for (bytes, padded, unpadded) in [
            ("", "", ""),
            ("f", "Zg==", "Zg"),
            ("fo", "Zm8=", "Zm8"),
            ("foo", "Zm9v", "Zm9v"),
            ("foob", "Zm9vYg==", "Zm9vYg"),
            ("fooba", "Zm9vYmE=", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy", "Zm9vYmFy"),
        ] {
            assert_eq!(decode(padded).unwrap(), bytes.as_bytes());
            assert_eq!(decode(unpadded).unwrap(), bytes.as_bytes());
            assert_eq!(encode_unpadded(bytes.as_bytes()), unpadded);
        }
    }

    #[test]
    fn not_base64() {
        assert_eq!(decode("Zm9v!"), None);
        assert_eq!(decode("Z"), None);
        assert_eq!(decode("Zg=a"), None);
        assert_eq!(decode("Zm9v===="), None);
    }
}
