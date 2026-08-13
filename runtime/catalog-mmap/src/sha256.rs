const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn digest(data: &[u8]) -> [u8; 32] {
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(data.len() + 72);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut state = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];

    for block in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (index, word) in block.chunks_exact(4).enumerate() {
            w[index] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for index in 16..64 {
            let s0 = w[index - 15].rotate_right(7)
                ^ w[index - 15].rotate_right(18)
                ^ (w[index - 15] >> 3);
            let s1 = w[index - 2].rotate_right(17)
                ^ w[index - 2].rotate_right(19)
                ^ (w[index - 2] >> 10);
            w[index] = w[index - 16]
                .wrapping_add(s0)
                .wrapping_add(w[index - 7])
                .wrapping_add(s1);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for index in 0..64 {
            let sigma1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(sigma1)
                .wrapping_add(choice)
                .wrapping_add(K[index])
                .wrapping_add(w[index]);
            let sigma0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = sigma0.wrapping_add(majority);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    let mut output = [0u8; 32];
    for (index, value) in state.iter().enumerate() {
        output[index * 4..index * 4 + 4].copy_from_slice(&value.to_be_bytes());
    }
    output
}

pub fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{digest, hex};

    #[test]
    fn known_vector() {
        assert_eq!(
            hex(&digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    // NIST CAVS ("SHA-256 ShortMsg"/"SHA-256 LongMsg" byte-oriented test vectors,
    // CAVS 11.0, generated 2011-03-15) taken from the official SHA test vector
    // package published at:
    //   https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip
    // (files SHA256ShortMsg.rsp / SHA256LongMsg.rsp). `Len` in that format is a
    // bit length; message bytes and digests are reproduced verbatim below.
    fn from_hex(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0);
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn check(msg_hex: &str, expected_hex: &str) {
        let msg = from_hex(msg_hex);
        assert_eq!(
            hex(&digest(&msg)),
            expected_hex,
            "mismatch for Msg={msg_hex}"
        );
    }

    #[test]
    fn cavs_short_msg_empty() {
        // Len = 0
        check(
            "",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
    }

    #[test]
    fn cavs_short_msg_1_byte() {
        // Len = 8
        check(
            "d3",
            "28969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c1",
        );
    }

    #[test]
    fn cavs_short_msg_2_bytes() {
        // Len = 16
        check(
            "11af",
            "5ca7133fa735326081558ac312c620eeca9970d1e70a4b95533d956f072d1f98",
        );
    }

    #[test]
    fn cavs_short_msg_3_bytes() {
        // Len = 24
        check(
            "b4190e",
            "dff2e73091f6c05e528896c4c831b9448653dc2ff043528f6769437bc7b975c2",
        );
    }

    #[test]
    fn cavs_short_msg_4_bytes() {
        // Len = 32
        check(
            "74ba2521",
            "b16aa56be3880d18cd41e68384cf1ec8c17680c45a02b1575dc1518923ae8b0e",
        );
    }

    #[test]
    fn cavs_short_msg_55_bytes_single_block_boundary() {
        // Len = 440. 55 data bytes + the 0x80 terminator land exactly at the
        // 56-byte mark, so this message fits in a single 64-byte block with no
        // zero padding before the length suffix.
        check(
            "3ebfb06db8c38d5ba037f1363e118550aad94606e26835a01af05078533cc25f2f39573c04b632f62f68c294ab31f2a3e2a1a0d8c2be51",
            "6595a2ef537a69ba8583dfbf7f5bec0ab1f93ce4c8ee1916eff44a93af5749c4",
        );
    }

    #[test]
    fn cavs_short_msg_56_bytes_spills_second_block() {
        // Len = 448. One byte past the single-block boundary: the 0x80
        // terminator no longer fits before the 56-byte padding mark, so this
        // message spills into a second 64-byte block.
        check(
            "2d52447d1244d2ebc28650e7b05654bad35b3a68eedc7f8515306b496d75f3e73385dd1b002625024b81a02f2fd6dffb6e6d561cb7d0bd7a",
            "cfb88d6faf2de3a69d36195acec2e255e2af2b7d933997f348e09f6ce5758360",
        );
    }

    #[test]
    fn cavs_short_msg_64_bytes_full_block_plus_padding_block() {
        // Len = 512. A message that is itself exactly one full block requires
        // an entire second block purely for padding and the length suffix.
        check(
            "5a86b737eaea8ee976a0a24da63e7ed7eefad18a101c1211e2b3650c5187c2a8a650547208251f6d4237e661c7bf4c77f335390394c37fa1a9f9be836ac28509",
            "42e61e174fbb3897d6dd6cef3dd2802fe67b331953b06114a65c772859dfc1aa",
        );
    }

    #[test]
    fn cavs_long_msg_163_bytes_three_blocks() {
        // Len = 1304 (163 bytes / 3 blocks) -- a multi-block message beyond
        // the two-block cases above.
        check(
            "451101250ec6f26652249d59dc974b7361d571a8101cdfd36aba3b5854d3ae086b5fdd4597721b66e3c0dc5d8c606d9657d0e323283a5217d1f53f2f284f57b85c8a61ac8924711f895c5ed90ef17745ed2d728abd22a5f7a13479a462d71b56c19a74a40b655c58edfe0a188ad2cf46cbf30524f65d423c837dd1ff2bf462ac4198007345bb44dbb7b1c861298cdf61982a833afc728fae1eda2f87aa2c9480858bec",
            "3c593aa539fdcdae516cdf2f15000f6634185c88f505b39775fb9ab137a10aa2",
        );
    }

    // The official CAVS ShortMsg/LongMsg vector sets step in fixed byte
    // increments (..., 64, ..., 163, ...) and do not include entries at
    // exactly 119 or 120 bytes -- the padding boundary one block later than
    // the 55/56-byte case above. These two vectors cover that boundary
    // directly: messages are the deterministic byte sequence `i % 256` for
    // `i` in `0..n`, with digests independently computed and cross-checked
    // against Python's standard-library `hashlib.sha256` (a separate,
    // long-established SHA-256 implementation, not the code under test here).
    #[test]
    fn boundary_119_bytes_second_block_single_block_padding() {
        // 119 data bytes + 0x80 lands exactly at the 120-byte mark (120 mod
        // 64 == 56), the second-block analogue of the 55-byte case: no zero
        // padding needed before the length suffix.
        let msg: Vec<u8> = (0..119u32).map(|i| (i % 256) as u8).collect();
        assert_eq!(
            hex(&digest(&msg)),
            "da18797ed7c3a777f0847f429724a2d8cd5138e6ed2895c3fa1a6d39d18f7ec6"
        );
    }

    #[test]
    fn boundary_120_bytes_spills_third_block() {
        // 120 data bytes: one byte past the boundary above, so the 0x80
        // terminator plus the mandatory zero padding spill into a third
        // 64-byte block.
        let msg: Vec<u8> = (0..120u32).map(|i| (i % 256) as u8).collect();
        assert_eq!(
            hex(&digest(&msg)),
            "f52b23db1fbb6ded89ef42a23ce0c8922c45f25c50b568a93bf1c075420bbb7c"
        );
    }
}
