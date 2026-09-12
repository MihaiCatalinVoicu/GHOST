//! Issuer API crate: wire types and gRPC service generated from `protocol/issuer/v1/issuer.proto`
//! (Phase 8 design §5.2), plus the wire sizes every client and the issuer check. The protocol
//! version itself has one definition, `ghost_issuer::PROTOCOL_VERSION`.
#![forbid(unsafe_code)]

/// Generated protobuf messages and gRPC service (`ghost.issuer.v1`).
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/ghost.issuer.v1.rs"));
}

/// `invoice_id`: 16 random bytes.
pub const INVOICE_ID_BYTES: usize = 16;
/// `claim_hash` and `claim_key`: 32 bytes each.
pub const CLAIM_BYTES: usize = 32;
/// `claim_id` of `ClaimPayout`: 16 random bytes.
pub const CLAIM_ID_BYTES: usize = 16;
/// One blinded message or blind signature (type 0x0002, RSA-2048).
pub const BLOCK_BYTES: usize = 256;
/// Largest pack layout: 5 weeks x 32 slots x 16 access positions + 2 invites + 1 credit (§4.2).
pub const MAX_LAYOUT_POSITIONS: usize = 2_563;
/// Most credits a credits-paid `RequestInvoice` may carry (§5.2).
pub const MAX_DISCOUNT_CREDITS: usize = 20;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_types_exist_and_numbering_is_the_design() {
        let req = proto::RequestInvoiceRequest {
            version: 1,
            rail: proto::Rail::Monero as i32,
            product: proto::Product::Pack as i32,
            ..Default::default()
        };
        assert_eq!(req.version, 1);
        assert_eq!(proto::Rail::Monero as i32, 1);
        assert_eq!(proto::InvoiceState::OtherRequestIssued as i32, 6);
        assert_eq!(proto::ClaimPayoutResult::AddressRejected as i32, 4);
        assert_eq!(proto::RefreshCreditResult::Replayed as i32, 2);
        assert_eq!(MAX_LAYOUT_POSITIONS, 5 * 32 * 16 + 3);
    }
}
