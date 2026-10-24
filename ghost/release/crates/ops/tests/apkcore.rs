//! Tests for the §6.5 core rule with a synthetic signed APK (a real-apksigner fixture lands with
//! the V-D5 matrix on a software key; V-D6 repeats it on the hardware token).

use ghost_release_ops::apkcore::{self, CoreError};

const MAGIC: &[u8; 16] = b"APK Sig Block 42";

/// Build an unsigned APK shape: local bytes ‖ central directory ‖ EOCD(cd_offset = local_len).
/// The central directory and EOCD carry no real zip semantics beyond what the rule reads.
fn unsigned_apk(local: &[u8], cd: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(local);
    let cd_offset = v.len() as u32;
    v.extend_from_slice(cd);
    // EOCD
    v.extend_from_slice(b"PK\x05\x06");
    v.extend_from_slice(&0u16.to_le_bytes()); // disk
    v.extend_from_slice(&0u16.to_le_bytes()); // cd disk
    v.extend_from_slice(&1u16.to_le_bytes()); // entries disk
    v.extend_from_slice(&1u16.to_le_bytes()); // entries total
    v.extend_from_slice(&(cd.len() as u32).to_le_bytes()); // cd size
    v.extend_from_slice(&cd_offset.to_le_bytes()); // cd offset
    v.extend_from_slice(&0u16.to_le_bytes()); // comment
    v
}

/// Wrap an unsigned APK into the signed shape: insert zero padding to a 4096 boundary and a
/// signing block whose single pair carries `payload`, and move the cd/eocd after the block.
fn signed_apk(unsigned: &[u8], payload: &[u8; 8]) -> Vec<u8> {
    // Parse the unsigned EOCD to find its cd.
    let eocd_at = unsigned.len() - 22;
    assert_eq!(&unsigned[eocd_at..eocd_at + 4], b"PK\x05\x06");
    let cd_size = u32::from_le_bytes(unsigned[eocd_at + 12..eocd_at + 16].try_into().unwrap());
    let cd_offset = u32::from_le_bytes(unsigned[eocd_at + 16..eocd_at + 20].try_into().unwrap());
    let local = &unsigned[..cd_offset as usize];
    let cd = &unsigned[cd_offset as usize..eocd_at];
    let e = local.len() as u64;
    let b = e + ((4096 - e % 4096) % 4096);
    // One pair: len(Q) + id(u32) + value. `s` counts pairs + size2 + magic (everything after
    // size1), matching apksigner and the §6.5 rule's `cd_offset - s - 8 = B`.
    let pair_value_len = 4 + payload.len() as u64; // pair len field counts id + value
    let pairs_len = 8 + pair_value_len;
    let s = pairs_len + 8 + 16;
    let mut v = Vec::new();
    v.extend_from_slice(local);
    v.extend(std::iter::repeat(0u8).take((b - e) as usize));
    v.extend_from_slice(&s.to_le_bytes()); // size1 at B
    v.extend_from_slice(&pair_value_len.to_le_bytes()); // pair len (id + value)
    v.extend_from_slice(&0x1234_5678u32.to_le_bytes()); // pair id
    v.extend_from_slice(payload);
    v.extend_from_slice(&s.to_le_bytes()); // size2
    v.extend_from_slice(MAGIC);
    let new_cd_offset = v.len() as u32;
    v.extend_from_slice(cd);
    v.extend_from_slice(b"PK\x05\x06");
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&1u16.to_le_bytes());
    v.extend_from_slice(&1u16.to_le_bytes());
    v.extend_from_slice(&cd_size.to_le_bytes());
    v.extend_from_slice(&new_cd_offset.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v
}

#[test]
fn core_equal_synthetic() {
    let local = vec![0xAA; 5000]; // E = 5000 -> B = 8192 (padding p = 3192)
    let cd = vec![0xBB; 100];
    let unsigned = unsigned_apk(&local, &cd);
    let signed = signed_apk(&unsigned, &[1, 2, 3, 4, 5, 6, 7, 8]);
    let (padding, ids) = apkcore::check_core(&signed, &unsigned).unwrap();
    assert_eq!(padding, 3192);
    assert_eq!(ids, vec![0x12345678]);
}

#[test]
fn core_sha256_form_matches() {
    use sha2::{Digest, Sha256};
    let unsigned = unsigned_apk(&vec![0xAA; 4096], &vec![0xBB; 40]); // E aligned: padding 0
    let signed = signed_apk(&unsigned, &[0; 8]);
    let expect: [u8; 32] = Sha256::digest(&unsigned).into();
    let (padding, _) = apkcore::check_core_sha256(&signed, unsigned.len() as u64, &expect).unwrap();
    assert_eq!(padding, 0);
}

#[test]
fn non_zero_padding_rejected() {
    let unsigned = unsigned_apk(&vec![0xAA; 5000], &vec![0xBB; 100]);
    let mut signed = signed_apk(&unsigned, &[0; 8]);
    // Corrupt one padding byte (at offset 5000, inside [E, B)).
    let idx = 5000usize;
    let byte = signed[idx];
    signed[idx] = byte ^ 0xFF;
    assert_eq!(
        apkcore::check_core(&signed, &unsigned),
        Err(CoreError::Padding)
    );
}

#[test]
fn different_unsigned_rejected() {
    let unsigned = unsigned_apk(&vec![0xAA; 5000], &vec![0xBB; 100]);
    let signed = signed_apk(&unsigned, &[0; 8]);
    let other = unsigned_apk(&vec![0xAA; 5001], &vec![0xBB; 100]);
    assert_eq!(
        apkcore::check_core(&signed, &other),
        Err(CoreError::CoreMismatch)
    );
}

#[test]
fn comment_rejected() {
    let unsigned = unsigned_apk(&vec![0xAA; 5000], &vec![0xBB; 100]);
    let mut signed = signed_apk(&unsigned, &[0; 8]);
    let last = signed.len() - 1;
    signed[last] = 1; // EOCD comment length low byte
    assert_eq!(apkcore::layout(&signed), Err(CoreError::Comment));
}

#[test]
fn truncated_block_footer_rejected() {
    let unsigned = unsigned_apk(&vec![0xAA; 100], &vec![0xBB; 50]);
    let signed = signed_apk(&unsigned, &[0; 8]);
    // Cut inside the block so the magic is gone.
    let cut = &signed[..signed.len() - 60];
    assert_eq!(apkcore::layout(cut), Err(CoreError::Eocd));
}
