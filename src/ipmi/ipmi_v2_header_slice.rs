use bitvec::{field::BitField, prelude::*, slice::BitSlice};

use super::{
    ipmi_header::AuthType,
    ipmi_v2_header::{IpmiV2Header, PayloadType},
};

pub struct IpmiV2HeaderSlice<'a> {
    slice: &'a [u8],
}

impl<'a> IpmiV2HeaderSlice<'a> {
    pub fn from_slice(slice: &'a [u8]) -> Result<IpmiV2HeaderSlice<'a>, std::io::ErrorKind> {
        println!("slice ipmi v2 header: {:x?}", slice);
        // todo: implement error checking
        Ok(IpmiV2HeaderSlice::<'a> {
            slice: unsafe { core::slice::from_raw_parts(slice.as_ptr(), slice.len()) },
        })
    }

    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    pub fn auth_type(&self) -> u8 {
        u8::from_be_bytes([self.slice[0]])
    }

    pub fn payload_byte(&self) -> u8 {
        u8::from_be_bytes([self.slice[1]])
    }

    pub fn payload_enc(&self) -> bool {
        BitSlice::<u8, Msb0>::from_element(&self.payload_byte())[0]
    }

    pub fn payload_auth(&self) -> bool {
        BitSlice::<u8, Msb0>::from_element(&self.payload_byte())[1]
    }

    pub fn payload_type(&self) -> PayloadType {
        PayloadType::from_u8(
            BitSlice::<u8, Msb0>::from_element(&self.payload_byte())[3..].load::<u8>(),
        )
    }

    pub fn oem_iana(&self) -> Option<u32> {
        match self.payload_type() {
            PayloadType::OEM => Some(u32::from_be_bytes([
                self.slice[2],
                self.slice[3],
                self.slice[4],
                self.slice[5],
            ])),
            _ => None,
        }
    }

    pub fn oem_payload_id(&self) -> Option<u16> {
        match self.payload_type() {
            PayloadType::OEM => Some(u16::from_be_bytes([self.slice[6], self.slice[7]])),
            _ => None,
        }
    }

    pub fn rmcp_plus_session_id(&self) -> u32 {
        match self.payload_type() {
            PayloadType::OEM => {
                u32::from_be_bytes([self.slice[8], self.slice[9], self.slice[10], self.slice[11]])
            }
            _ => u32::from_be_bytes([self.slice[2], self.slice[3], self.slice[4], self.slice[5]]),
        }
    }

    pub fn session_seq_number(&self) -> u32 {
        match self.payload_type() {
            PayloadType::OEM => u32::from_be_bytes([
                self.slice[12],
                self.slice[13],
                self.slice[14],
                self.slice[15],
            ]),
            _ => u32::from_be_bytes([self.slice[6], self.slice[7], self.slice[8], self.slice[9]]),
        }
    }

    pub fn payload_length(&self) -> u16 {
        match self.payload_type() {
            PayloadType::OEM => u16::from_le_bytes([self.slice[16], self.slice[17]]),
            _ => u16::from_le_bytes([self.slice[10], self.slice[11]]),
        }
    }

    pub fn to_header(&self) -> IpmiV2Header {
        IpmiV2Header {
            auth_type: AuthType::from_u8(self.auth_type()),
            payload_enc: self.payload_enc(),
            payload_auth: self.payload_auth(),
            payload_type: self.payload_type(),
            oem_iana: self.oem_iana(),
            oem_payload_id: self.oem_payload_id(),
            rmcp_plus_session_id: self.rmcp_plus_session_id(),
            session_seq_number: self.session_seq_number(),
            payload_length: self.payload_length(),
        }
    }
}
