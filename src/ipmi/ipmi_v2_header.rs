use arrayvec::ArrayVec;
use bitvec::{prelude::*, vec::BitVec};

use crate::ipmi::ipmi_v2_header_slice::IpmiV2HeaderSlice;

use super::ipmi_header::{AuthType, IpmiHeader};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
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

impl IpmiV2Header {
    pub const MIN_LEN: usize = 12;

    pub const MAX_LEN: usize = 18;

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

    pub fn from_slice(slice: &[u8]) -> Result<(IpmiV2Header, &[u8]), std::io::ErrorKind> {
        let h = IpmiV2HeaderSlice::from_slice(slice)?;
        Ok((h.to_header(), &slice[h.slice().len()..]))
    }

    pub fn to_bytes(&self) -> ArrayVec<u8, { IpmiHeader::MAX_LEN }> {
        match self.payload_type {
            PayloadType::OEM => {
                let oem_iana_be = self.oem_iana.unwrap().to_le_bytes();
                let oem_payload_id_be = self.oem_payload_id.unwrap().to_le_bytes();
                let rmcp_ses_be = self.rmcp_plus_session_id.to_le_bytes();
                let ses_seq_be = self.session_seq_number.to_le_bytes();
                let len_be = self.payload_length.to_le_bytes();

                let mut result = ArrayVec::new();
                result.extend([
                    self.auth_type.to_u8(),
                    {
                        let mut bv: BitVec<u8, Msb0> = bitvec![u8, Msb0; 0;8];
                        bv.set(0, self.payload_enc);
                        bv.set(1, self.payload_auth);
                        // bv[0..0].store::<u8>(self.payload_enc as u8);
                        // bv[1..1].store::<u8>(self.payload_auth as u8);
                        bv[2..].store::<u8>(self.payload_type.to_u8());
                        let payload_type = bv[..].load::<u8>();
                        payload_type
                    },
                    oem_iana_be[0],
                    oem_iana_be[1],
                    oem_iana_be[2],
                    oem_iana_be[3],
                    oem_payload_id_be[0],
                    oem_payload_id_be[1],
                    rmcp_ses_be[0],
                    rmcp_ses_be[1],
                    rmcp_ses_be[2],
                    rmcp_ses_be[3],
                    ses_seq_be[0],
                    ses_seq_be[1],
                    ses_seq_be[2],
                    ses_seq_be[3],
                    len_be[0],
                    len_be[1],
                ]);

                unsafe { result.set_len(18) };

                result
            }
            _ => {
                let rmcp_ses_be = self.rmcp_plus_session_id.to_le_bytes();
                let ses_seq_be = self.session_seq_number.to_le_bytes();
                let len_be = self.payload_length.to_le_bytes();

                let mut result = ArrayVec::new();
                result.extend([
                    self.auth_type.to_u8(),
                    {
                        let mut bv: BitVec<u8, Msb0> = bitvec![u8, Msb0; 0;8];
                        bv.set(0, self.payload_enc);
                        bv.set(1, self.payload_auth);
                        // bv[0..0].store::<u8>(self.payload_enc as u8);
                        // bv[1..1].store::<u8>(self.payload_auth as u8);
                        bv[2..].store::<u8>(self.payload_type.to_u8());
                        let payload_type = bv[..].load::<u8>();
                        payload_type
                    },
                    rmcp_ses_be[0],
                    rmcp_ses_be[1],
                    rmcp_ses_be[2],
                    rmcp_ses_be[3],
                    ses_seq_be[0],
                    ses_seq_be[1],
                    ses_seq_be[2],
                    ses_seq_be[3],
                    len_be[0],
                    len_be[1],
                ]);

                unsafe { result.set_len(12) };

                result
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
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
    Reserved,
}

impl PayloadType {
    pub fn from_u8(payload_type: u8) -> PayloadType {
        match payload_type {
            0x00 => PayloadType::IPMI,
            0x01 => PayloadType::SOL,
            0x02 => PayloadType::OEM,
            0x10 => PayloadType::RcmpOpenSessionRequest,
            0x11 => PayloadType::RcmpOpenSessionResponse,
            0x12 => PayloadType::RAKP1,
            0x13 => PayloadType::RAKP2,
            0x14 => PayloadType::RAKP3,
            0x15 => PayloadType::RAKP4,
            _ => PayloadType::Reserved,
        }
    }

    pub fn to_u8(&self) -> u8 {
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
            PayloadType::Reserved => 0xff,
        }
    }
}
