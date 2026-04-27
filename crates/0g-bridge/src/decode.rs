//! SSZ decoding of EIP-7685 type-`0x05` bridge request payload.

use crate::{BRIDGE_REQUEST_TYPE, MAX_BRIDGE_MESSAGES_PER_BLOCK};
use alloc::vec::Vec;
use alloy_primitives::{Address, FixedBytes, U256};
use ssz::{Decode, DecodeError};
use ssz_derive::{Decode as SszDecode, Encode as SszEncode};

/// SSZ container matching the CL Go struct field-for-field.
///
/// Layout (canonical, frozen by `docs/plans/bridge-schemas.md`):
///
/// | Field        | Type     | Bytes | Endianness |
/// |--------------|----------|-------|------------|
/// | SrcChainID   | U64      | 8     | LE         |
/// | DstChainID   | U64      | 8     | LE         |
/// | Nonce        | U64      | 8     | LE         |
/// | LocalToken   | Bytes20  | 20    | raw        |
/// | Recipient    | Bytes20  | 20    | raw        |
/// | Amount       | Bytes32  | 32    | BE         |
/// | Mode         | U8       | 1     | -          |
/// | SrcBlock     | U64      | 8     | LE         |
/// | **Total**    |          | 105   |            |
///
/// `Amount` is stored big-endian on the wire so that it round-trips into a `uint256` ABI
/// argument without re-shuffling bytes.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode)]
pub struct BridgeMessage {
    /// Source chain EL chainId.
    pub src_chain_id: u64,
    /// Destination chain EL chainId. EL drops this field before ABI-encoding (the destination
    /// is implicit — it's the chain executing the system call).
    pub dst_chain_id: u64,
    /// Per-`(srcCID, dstCID)` strictly monotonic nonce assigned by the source-chain Bridge.
    pub nonce: u64,
    /// Address of the token on the **destination** chain (CL poller already resolved the
    /// remote-token mapping from the source chain's `BridgeOut.remoteToken`).
    pub local_token: FixedBytes<20>,
    /// Recipient address on the destination chain.
    pub recipient: FixedBytes<20>,
    /// Big-endian uint256 amount.
    pub amount: FixedBytes<32>,
    /// Source-chain bridge mode (`0 = LockRelease`, `1 = MintBurn`). Audit-only — the
    /// destination contract decides execution mode from its own `tokens[localToken].mode`.
    pub mode: u8,
    /// Source-chain block height where the originating `BridgeOut` event was emitted.
    /// Audit-only.
    pub src_block: u64,
}

impl BridgeMessage {
    /// Convenience accessor: amount as `U256` (big-endian decoded).
    pub fn amount_u256(&self) -> U256 {
        U256::from_be_bytes::<32>(self.amount.0)
    }

    /// Convenience accessor: local token as `Address`.
    pub fn local_token_address(&self) -> Address {
        Address::from(self.local_token.0)
    }

    /// Convenience accessor: recipient as `Address`.
    pub fn recipient_address(&self) -> Address {
        Address::from(self.recipient.0)
    }
}

/// Variable-length list `List[BridgeMessage, MaxBridgeMessagesPerBlock]` SSZ container.
///
/// Encoded as a transparent SSZ list — the cap is enforced post-decode by
/// [`decode_bridge_messages`] rather than by the SSZ derive (which has no `max_len` attr in
/// `ethereum_ssz_derive`).
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode)]
#[ssz(struct_behaviour = "transparent")]
pub struct BridgeRequests {
    /// Decoded messages. Length must be `<= MAX_BRIDGE_MESSAGES_PER_BLOCK`; enforced at
    /// decode time. CL builder pre-sorts by `(SrcChainID, DstChainID, Nonce)`; EL preserves
    /// input order.
    pub messages: Vec<BridgeMessage>,
}

/// Errors that can occur when decoding a type-`0x05` request payload.
#[derive(Debug, thiserror::Error)]
pub enum BridgeDecodeError {
    /// Type byte was missing or did not match `0x05`.
    #[error("expected EIP-7685 request type byte 0x05, got 0x{0:02x}")]
    WrongTypeByte(u8),

    /// Empty payload (no type byte).
    #[error("empty bridge request payload")]
    Empty,

    /// SSZ decoder rejected the bytes.
    #[error("ssz decode failed: {0:?}")]
    Ssz(DecodeError),

    /// Decoded list exceeds [`MAX_BRIDGE_MESSAGES_PER_BLOCK`].
    #[error("bridge request contains {got} messages, exceeds cap of {MAX_BRIDGE_MESSAGES_PER_BLOCK}")]
    TooManyMessages {
        /// Actual decoded length.
        got: usize,
    },

    /// `mode` byte is neither `0` (LockRelease) nor `1` (MintBurn).
    #[error("invalid bridge mode byte: 0x{0:02x}")]
    InvalidMode(u8),
}

impl From<DecodeError> for BridgeDecodeError {
    fn from(value: DecodeError) -> Self {
        Self::Ssz(value)
    }
}

/// Decodes a full EIP-7685 type-`0x05` request entry: leading type byte stripped, then SSZ
/// container body, then length cap and mode-byte sanity checks.
///
/// The expected wire format is:
///
/// ```text
/// request_bytes = 0x05 || ssz_bytes(BridgeRequests)
/// ```
///
/// Note: this function expects the **entire** entry including the leading type byte. Callers
/// that have already stripped the type byte should call [`decode_bridge_messages`] instead.
pub fn decode_bridge_request(bytes: &[u8]) -> Result<Vec<BridgeMessage>, BridgeDecodeError> {
    let first = bytes.first().ok_or(BridgeDecodeError::Empty)?;
    if *first != BRIDGE_REQUEST_TYPE {
        return Err(BridgeDecodeError::WrongTypeByte(*first));
    }
    decode_bridge_messages(&bytes[1..])
}

/// Decodes the SSZ body (`BridgeRequests`) without the EIP-7685 type byte.
pub fn decode_bridge_messages(body: &[u8]) -> Result<Vec<BridgeMessage>, BridgeDecodeError> {
    let requests = BridgeRequests::from_ssz_bytes(body)?;

    if requests.messages.len() > MAX_BRIDGE_MESSAGES_PER_BLOCK {
        return Err(BridgeDecodeError::TooManyMessages { got: requests.messages.len() });
    }
    // Validate mode bytes early so callers don't have to.
    for msg in &requests.messages {
        let _ = crate::BridgeMode::try_from(msg.mode)?;
    }
    Ok(requests.messages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssz::Encode;

    fn sample_msg(nonce: u64) -> BridgeMessage {
        BridgeMessage {
            src_chain_id: 16700,
            dst_chain_id: 16702,
            nonce,
            local_token: FixedBytes([1; 20]),
            recipient: FixedBytes([2; 20]),
            amount: FixedBytes(U256::from(1_000_000_000_000_000_000u128).to_be_bytes::<32>()),
            mode: 1,
            src_block: 42,
        }
    }

    #[test]
    fn roundtrip_single_message() {
        let m = sample_msg(7);
        let body = BridgeRequests { messages: vec![m.clone()] }.as_ssz_bytes();
        let mut wire = Vec::with_capacity(body.len() + 1);
        wire.push(BRIDGE_REQUEST_TYPE);
        wire.extend_from_slice(&body);
        let decoded = decode_bridge_request(&wire).expect("decode happy path");
        assert_eq!(decoded, vec![m]);
    }

    #[test]
    fn empty_message_list_roundtrips() {
        let body = BridgeRequests { messages: vec![] }.as_ssz_bytes();
        let mut wire = vec![BRIDGE_REQUEST_TYPE];
        wire.extend_from_slice(&body);
        let decoded = decode_bridge_request(&wire).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn rejects_wrong_type_byte() {
        let body = BridgeRequests { messages: vec![sample_msg(1)] }.as_ssz_bytes();
        let mut wire = vec![0x04];
        wire.extend_from_slice(&body);
        let err = decode_bridge_request(&wire).unwrap_err();
        assert!(matches!(err, BridgeDecodeError::WrongTypeByte(0x04)), "got {err:?}");
    }

    #[test]
    fn rejects_empty_payload() {
        let err = decode_bridge_request(&[]).unwrap_err();
        assert!(matches!(err, BridgeDecodeError::Empty));
    }

    #[test]
    fn rejects_malformed_ssz() {
        // Type byte present but truncated / garbage SSZ body.
        let wire = vec![BRIDGE_REQUEST_TYPE, 0xff, 0xff];
        let err = decode_bridge_request(&wire).unwrap_err();
        assert!(matches!(err, BridgeDecodeError::Ssz(_)), "got {err:?}");
    }

    #[test]
    fn enforces_message_cap() {
        // Build a list with cap+1 messages.
        let many: Vec<BridgeMessage> =
            (0..(MAX_BRIDGE_MESSAGES_PER_BLOCK + 1) as u64).map(sample_msg).collect();
        let body = BridgeRequests { messages: many }.as_ssz_bytes();
        let mut wire = vec![BRIDGE_REQUEST_TYPE];
        wire.extend_from_slice(&body);
        let err = decode_bridge_request(&wire).unwrap_err();
        match err {
            BridgeDecodeError::Ssz(_) | BridgeDecodeError::TooManyMessages { .. } => {}
            other => panic!("expected ssz/cap rejection, got {other:?}"),
        }
    }

    #[test]
    fn at_cap_is_accepted() {
        let exactly_cap: Vec<BridgeMessage> =
            (0..MAX_BRIDGE_MESSAGES_PER_BLOCK as u64).map(sample_msg).collect();
        let body = BridgeRequests { messages: exactly_cap.clone() }.as_ssz_bytes();
        let mut wire = vec![BRIDGE_REQUEST_TYPE];
        wire.extend_from_slice(&body);
        let decoded = decode_bridge_request(&wire).expect("at cap should succeed");
        assert_eq!(decoded.len(), MAX_BRIDGE_MESSAGES_PER_BLOCK);
        assert_eq!(decoded, exactly_cap);
    }

    #[test]
    fn rejects_invalid_mode_byte() {
        let mut bad = sample_msg(1);
        bad.mode = 0xFF;
        let body = BridgeRequests { messages: vec![bad] }.as_ssz_bytes();
        let mut wire = vec![BRIDGE_REQUEST_TYPE];
        wire.extend_from_slice(&body);
        let err = decode_bridge_request(&wire).unwrap_err();
        assert!(matches!(err, BridgeDecodeError::InvalidMode(0xFF)), "got {err:?}");
    }

    #[test]
    fn amount_be_decode_matches_u256() {
        let m = sample_msg(1);
        assert_eq!(m.amount_u256(), U256::from(1_000_000_000_000_000_000u128));
    }
}
