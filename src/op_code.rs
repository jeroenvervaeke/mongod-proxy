//! Wire-protocol opcode tag carried in every MongoDB message header.
//!
//! Every MongoDB wire frame begins with a 16-byte header whose last 4 bytes
//! identify the operation. This module models the three opcodes the proxy
//! understands; encountering any other value is treated as a parse error
//! rather than silently passed through.

/// The opcode carried in a [`MessageHeader`](crate::header::MessageHeader).
///
/// Only the three values still in use by modern MongoDB clients are modelled
/// here. The retired legacy commands (`OP_INSERT`, `OP_UPDATE`, `OP_DELETE`,
/// `OP_KILL_CURSORS`, `OP_GET_MORE`) intentionally are not — encountering
/// them on the wire is reported as [`OPCodeParseError::UnsupportedOpCode`].
///
/// # Examples
///
/// Round-trip an opcode through its on-the-wire byte representation:
///
/// ```
/// use mongod_proxy::op_code::OPCode;
///
/// let bytes = OPCode::Msg.to_le_bytes();
/// assert_eq!(bytes, [0xDD, 0x07, 0x00, 0x00]); // 2013 little-endian
/// assert_eq!(OPCode::from_le_bytes(bytes), Ok(OPCode::Msg));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OPCode {
    /// `OP_MSG` (wire id `2013`). The current message format used for every
    /// command on modern MongoDB versions.
    Msg,
    /// `OP_QUERY` (wire id `2004`). Legacy query format. Drivers still use it
    /// during the initial handshake (`isMaster` / `hello`) when they don't yet
    /// know the server's wire version.
    Query,
    /// `OP_REPLY` (wire id `1`). Legacy reply format paired with [`OPCode::Query`].
    Reply,
}

/// Failure to recognise the opcode in a message header.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum OPCodeParseError {
    /// The four header bytes decoded to a value that is not one of the
    /// supported opcodes. The decoded integer is included so callers can log
    /// or surface it.
    #[error("invalid opcode: {0}")]
    UnsupportedOpCode(i32),
}

const OP_REPLY: [u8; 4] = i32::to_le_bytes(1);
const OP_QUERY: [u8; 4] = i32::to_le_bytes(2004);
const OP_MSG: [u8; 4] = i32::to_le_bytes(2013);

impl OPCode {
    /// Parses the trailing four bytes of a wire-protocol header.
    ///
    /// # Errors
    ///
    /// Returns [`OPCodeParseError::UnsupportedOpCode`] if the bytes don't
    /// match one of the three supported opcodes.
    ///
    /// # Examples
    ///
    /// ```
    /// use mongod_proxy::op_code::{OPCode, OPCodeParseError};
    ///
    /// assert_eq!(OPCode::from_le_bytes([0xD4, 0x07, 0x00, 0x00]), Ok(OPCode::Query));
    /// assert_eq!(
    ///     OPCode::from_le_bytes([0xAA, 0x00, 0x00, 0x00]),
    ///     Err(OPCodeParseError::UnsupportedOpCode(0xAA)),
    /// );
    /// ```
    pub fn from_le_bytes(bytes: [u8; 4]) -> Result<OPCode, OPCodeParseError> {
        match bytes {
            OP_MSG => Ok(OPCode::Msg),
            OP_QUERY => Ok(OPCode::Query),
            OP_REPLY => Ok(OPCode::Reply),
            _ => Err(OPCodeParseError::UnsupportedOpCode(i32::from_le_bytes(
                bytes,
            ))),
        }
    }

    /// Encodes the opcode as the four little-endian bytes that appear at the
    /// end of a wire-protocol header.
    pub fn to_le_bytes(&self) -> [u8; 4] {
        match self {
            OPCode::Msg => OP_MSG,
            OPCode::Query => OP_QUERY,
            OPCode::Reply => OP_REPLY,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    #[rstest]
    #[case::unsupported_opcode([0xAA, 0x00, 0x00, 0x00], Err(OPCodeParseError::UnsupportedOpCode(0xAA)))]
    #[case::reply([0x01, 0x00, 0x00, 0x00], Ok(OPCode::Reply))]
    #[case::query([0xD4, 0x07, 0x00, 0x00], Ok(OPCode::Query))]
    #[case::msg([0xDD, 0x07, 0x00, 0x00], Ok(OPCode::Msg))]
    fn decode(#[case] bytes: [u8; 4], #[case] expected: Result<OPCode, OPCodeParseError>) {
        assert_eq!(expected, OPCode::from_le_bytes(bytes));
    }

    #[rstest]
    #[case::reply(OPCode::Reply, [0x01, 0x00, 0x00, 0x00])]
    #[case::query(OPCode::Query, [0xD4, 0x07, 0x00, 0x00])]
    #[case::msg(OPCode::Msg, [0xDD, 0x07, 0x00, 0x00])]
    fn encode(#[case] code: OPCode, #[case] expected: [u8; 4]) {
        assert_eq!(expected, code.to_le_bytes());
    }
}
