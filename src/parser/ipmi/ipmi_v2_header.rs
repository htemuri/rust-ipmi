use bitvec::{prelude::*, vec::BitVec};

use crate::err::{IpmiHeaderError, IpmiV2HeaderError};

use super::ipmi_header::AuthType;

#[derive(Clone, Copy, Debug)]
pub struct IpmiV2Header {
    pub auth_type: AuthType,
    pub payload_enc: bool,
    pub payload_auth: bool,
    pub payload_type: PayloadType,
    pub oem_iana: Option<u32>,
    pub oem_payload_id: Option<u16>,
    pub rmcp_plus_session_id: u32,
    pub session_seq_number: u32,
    pub payload_length: u16,
}

impl TryFrom<&[u8]> for IpmiV2Header {
    type Error = IpmiHeaderError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if (value.len() != 12) && (value.len() != 18) {
            Err(IpmiV2HeaderError::WrongLength)?
        }

        let auth_type: AuthType = value[0].try_into()?;
        let payload_bit_slice = BitSlice::<u8, Msb0>::from_element(&value[1]);
        let payload_enc = payload_bit_slice[0];
        let payload_auth = payload_bit_slice[1];
        let payload_type: PayloadType = payload_bit_slice[3..].load::<u8>().try_into()?;
        let oem_iana: Option<u32>;
        let oem_payload_id: Option<u16>;
        let rmcp_plus_session_id: u32;
        let session_seq_number: u32;
        let payload_length: u16;
        match payload_type {
            PayloadType::OEM => {
                if value.len() != 18 {
                    Err(IpmiV2HeaderError::WrongLength)?
                }
                oem_iana = Some(u32::from_be_bytes([value[2], value[3], value[4], value[5]]));
                oem_payload_id = Some(u16::from_be_bytes([value[6], value[7]]));
                rmcp_plus_session_id =
                    u32::from_be_bytes([value[8], value[9], value[10], value[11]]);
                session_seq_number =
                    u32::from_be_bytes([value[12], value[13], value[14], value[15]]);
                payload_length = u16::from_le_bytes([value[16], value[17]]);
            }
            _ => {
                oem_iana = None;
                oem_payload_id = None;
                rmcp_plus_session_id = u32::from_be_bytes([value[2], value[3], value[4], value[5]]);
                session_seq_number = u32::from_be_bytes([value[6], value[7], value[8], value[9]]);
                payload_length = u16::from_le_bytes([value[10], value[11]]);
            }
        }

        Ok(IpmiV2Header {
            auth_type,
            payload_enc,
            payload_auth,
            payload_type,
            oem_iana,
            oem_payload_id,
            rmcp_plus_session_id,
            session_seq_number,
            payload_length,
        })
    }
}

impl Into<Vec<u8>> for IpmiV2Header {
    fn into(self) -> Vec<u8> {
        match self.payload_type {
            PayloadType::OEM => {
                let oem_iana_be = self.oem_iana.unwrap().to_le_bytes();
                let oem_payload_id_be = self.oem_payload_id.unwrap().to_le_bytes();
                let rmcp_ses_be = self.rmcp_plus_session_id.to_le_bytes();
                let ses_seq_be = self.session_seq_number.to_le_bytes();
                let len_be = self.payload_length.to_le_bytes();

                let mut result = Vec::new();
                result.extend([self.auth_type.into(), {
                    let mut bv: BitVec<u8, Msb0> = bitvec![u8, Msb0; 0;8];
                    bv.set(0, self.payload_enc);
                    bv.set(1, self.payload_auth);
                    bv[2..].store::<u8>(self.payload_type.into());
                    let payload_type = bv[..].load::<u8>();
                    payload_type
                }]);
                result.extend(oem_iana_be);
                result.extend(oem_payload_id_be);
                result.extend(rmcp_ses_be);
                result.extend(ses_seq_be);
                result.extend(len_be);
                result
            }
            _ => {
                let rmcp_ses_be = self.rmcp_plus_session_id.to_le_bytes();
                let ses_seq_be = self.session_seq_number.to_le_bytes();
                let len_be = self.payload_length.to_le_bytes();

                let mut result = Vec::new();
                result.extend([self.auth_type.into(), {
                    let mut bv: BitVec<u8, Msb0> = bitvec![u8, Msb0; 0;8];
                    bv.set(0, self.payload_enc);
                    bv.set(1, self.payload_auth);
                    bv[2..].store::<u8>(self.payload_type.into());
                    let payload_type = bv[..].load::<u8>();
                    payload_type
                }]);
                result.extend(rmcp_ses_be);
                result.extend(ses_seq_be);
                result.extend(len_be);
                result
            }
        }
    }
}

impl IpmiV2Header {
    pub fn new(
        auth_type: AuthType,
        payload_enc: bool,
        payload_auth: bool,
        payload_type: PayloadType,
        rmcp_plus_session_id: u32,
        session_seq_number: u32,
        payload_length: u16,
    ) -> IpmiV2Header {
        IpmiV2Header {
            auth_type,
            payload_enc,
            payload_auth,
            payload_type,
            oem_iana: None,
            oem_payload_id: None,
            rmcp_plus_session_id,
            session_seq_number,
            payload_length,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum PayloadType {
    IPMI,
    SOL,
    OEM,
    RcmpOpenSessionRequest,
    RcmpOpenSessionResponse,
    RAKP1,
    RAKP2,
    RAKP3,
    RAKP4,
}

impl TryFrom<u8> for PayloadType {
    type Error = IpmiV2HeaderError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(PayloadType::IPMI),
            0x01 => Ok(PayloadType::SOL),
            0x02 => Ok(PayloadType::OEM),
            0x10 => Ok(PayloadType::RcmpOpenSessionRequest),
            0x11 => Ok(PayloadType::RcmpOpenSessionResponse),
            0x12 => Ok(PayloadType::RAKP1),
            0x13 => Ok(PayloadType::RAKP2),
            0x14 => Ok(PayloadType::RAKP3),
            0x15 => Ok(PayloadType::RAKP4),
            _ => Err(IpmiV2HeaderError::UnsupportedPayloadType(value)),
        }
    }
}

impl Into<u8> for PayloadType {
    fn into(self) -> u8 {
        match &self {
            PayloadType::IPMI => 0x00,
            PayloadType::SOL => 0x01,
            PayloadType::OEM => 0x02,
            PayloadType::RcmpOpenSessionRequest => 0x10,
            PayloadType::RcmpOpenSessionResponse => 0x11,
            PayloadType::RAKP1 => 0x12,
            PayloadType::RAKP2 => 0x13,
            PayloadType::RAKP3 => 0x14,
            PayloadType::RAKP4 => 0x15,
        }
    }
}
