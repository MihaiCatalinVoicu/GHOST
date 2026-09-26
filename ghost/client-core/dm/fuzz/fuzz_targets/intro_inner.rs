//! `dm-fuzz` target `intro_inner` (Phase 9 design §16.2 `dm-fuzz`, §6.4, §6.5, §22.35): the intro
//! inner layer. An attacker who encapsulates to a generation's X-Wing key holds the inner key, so
//! the inner plaintext is attacker-chosen: the fixture seals it under that key and
//! `open_intro_checked` decapsulates, opens and parses it (kind, card, binding minute and
//! signature, `reply_seed`, the L1 length and the zero padding), then parses the Olm PreKey header
//! and verifies binding v3 and the fallback key. The modes: the inner plaintext alone; the whole
//! envelope through the card-keyed outer layer; an attacker's ciphertext and inner bytes (the
//! decapsulation of bytes nobody encapsulated); and a re-signed inner layer around an attacker's
//! L1, which must open whenever that L1 is a canonical PreKey message that fits.
#![no_main]

use ghost_client_dm::binding::{self, BindingV3};
use ghost_client_dm::olm::message::{self, L1Header};
use ghost_client_dm::seal::{self, IntroOuter, SealMode, KIND_OLM_PREKEY};
use ghost_client_dm::{card, pq, sign};
use ghost_client_dm_fuzz::{array, bucket, fixture, tail, Fixture};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let f = fixture();
    let bucket = bucket(mode >> 2);
    let context = f.intro_context(bucket);
    match mode % 4 {
        0 => {
            let outer = f.intro_outer(bucket, f.seal_intro_inner(bucket, rest));
            let _ = seal::open_intro_checked(&f.gen_seed, &context, &outer, &f.fallback_key);
        }
        1 => {
            let mut body = Vec::new();
            body.extend_from_slice(&array::<4>(rest, 0));
            body.extend_from_slice(&f.ciphertext);
            body.extend_from_slice(&f.seal_intro_inner(bucket, tail(rest, 4)));
            let blob = f
                .seal_envelope(
                    &f.card_seal_key(),
                    bucket,
                    SealMode::Intro,
                    SealMode::Intro.as_u8(),
                    &[0u8; 32],
                    &body,
                )
                .expect("gen_id, the ciphertext and the inner layer fill the outer body exactly");
            let outer = seal::open_intro_outer(&f.card_seal_key(), &f.namespace, &blob)
                .expect("an envelope under the card key opens");
            let _ = seal::open_intro_checked(&f.gen_seed, &context, &outer, &f.fallback_key);
        }
        2 => {
            let outer = IntroOuter {
                gen_id: f.gen_id,
                ciphertext: array::<{ pq::CIPHERTEXT_BYTES }>(rest, 0).to_vec(),
                inner: tail(rest, pq::CIPHERTEXT_BYTES).to_vec(),
                bucket,
            };
            assert!(
                seal::open_intro_checked(&f.gen_seed, &context, &outer, &f.fallback_key).is_err(),
                "no inner layer opens without the key its ciphertext shares"
            );
        }
        _ => {
            let binding_minute = u32::from_be_bytes(array::<4>(rest, 0));
            let reply_seed = array::<32>(rest, 4);
            let l1 = tail(rest, 36);
            let Ok(L1Header::PreKey {
                identity_key,
                base_key,
                one_time_key,
                ..
            }) = message::parse(l1, true)
            else {
                return;
            };
            let sender_card = card::build(
                &f.sender_seed,
                0,
                &ghost_client_dm::derive::CardSecret::from_bytes([0x13; 32]),
            )
            .encode();
            let signature = binding::sign(
                &f.sender_seed,
                &BindingV3 {
                    oi_a: &identity_key,
                    card_index_a: 0,
                    recipient_namespace: &f.namespace,
                    binding_minute,
                    gen_id_b: f.gen_id,
                    xwing_ct: &f.ciphertext,
                    base_key_a: &base_key,
                    oi_b: &f.oi_recipient,
                },
            );
            let mut plain = vec![KIND_OLM_PREKEY];
            plain.extend_from_slice(&sender_card);
            plain.extend_from_slice(&binding_minute.to_be_bytes());
            plain.extend_from_slice(&signature);
            plain.extend_from_slice(&reply_seed);
            plain.extend_from_slice(&(l1.len() as u32).to_be_bytes());
            plain.extend_from_slice(l1);
            let fits = plain.len() <= Fixture::intro_inner_len(bucket);
            let outer = f.intro_outer(bucket, f.seal_intro_inner(bucket, &plain));
            let opened = seal::open_intro_checked(&f.gen_seed, &context, &outer, &one_time_key);
            if fits {
                let (opened, _) =
                    opened.expect("an honest inner layer around a canonical PreKey opens");
                assert_eq!(opened.l1, l1);
                assert_eq!(opened.binding_minute, binding_minute);
                assert_eq!(opened.reply_seed.as_bytes(), &reply_seed);
                assert_eq!(
                    sign::public_key(&f.sender_seed),
                    card::parse(&opened.sender_card)
                        .map(|c| c.identity_pk)
                        .expect("the sender card")
                );
            } else {
                assert!(opened.is_err());
            }
        }
    }
});
