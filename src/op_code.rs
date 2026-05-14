#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OPCode {
    Msg,
    Query,
    Reply,
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum OPCodeParseError {
    #[error("invalid opcode: {0}")]
    UnsupportedOpCode(i32),
}

const OP_REPLY: [u8; 4] = i32::to_le_bytes(1);
const OP_QUERY: [u8; 4] = i32::to_le_bytes(2004);
const OP_MSG: [u8; 4] = i32::to_le_bytes(2013);

impl OPCode {
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
