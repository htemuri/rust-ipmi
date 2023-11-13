use super::{ipmi_header::AuthType, ipmi_v1_header::IpmiV1Header};

#[derive(Debug)]
pub struct IpmiV1HeaderSlice<'a> {
    slice: &'a [u8],
}

impl<'a> IpmiV1HeaderSlice<'a> {
    pub fn from_slice(slice: &'a [u8]) -> Result<IpmiV1HeaderSlice<'a>, std::io::ErrorKind> {
        // todo: implement error checking
        Ok(IpmiV1HeaderSlice::<'a> {
            slice: unsafe { core::slice::from_raw_parts(slice.as_ptr(), slice.len()) },
        })
    }

    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    pub fn auth_type(&self) -> u8 {
        u8::from_be_bytes([self.slice[0]])
    }
    pub fn session_seq_number(&self) -> u32 {
        unsafe {
            u32::from_be_bytes([
                *self.slice.as_ptr().add(1),
                *self.slice.as_ptr().add(2),
                *self.slice.as_ptr().add(3),
                *self.slice.as_ptr().add(4),
            ])
        }
    }
    pub fn session_id(&self) -> u32 {
        unsafe {
            u32::from_be_bytes([
                *self.slice.as_ptr().add(5),
                *self.slice.as_ptr().add(6),
                *self.slice.as_ptr().add(7),
                *self.slice.as_ptr().add(8),
            ])
        }
    }
    pub fn auth_code(&self) -> u128 {
        unsafe {
            u128::from_be_bytes([
                *self.slice.as_ptr().add(9),
                *self.slice.as_ptr().add(10),
                *self.slice.as_ptr().add(11),
                *self.slice.as_ptr().add(12),
                *self.slice.as_ptr().add(13),
                *self.slice.as_ptr().add(14),
                *self.slice.as_ptr().add(15),
                *self.slice.as_ptr().add(16),
                *self.slice.as_ptr().add(17),
                *self.slice.as_ptr().add(18),
                *self.slice.as_ptr().add(19),
                *self.slice.as_ptr().add(20),
                *self.slice.as_ptr().add(21),
                *self.slice.as_ptr().add(22),
                *self.slice.as_ptr().add(23),
                *self.slice.as_ptr().add(24),
            ])
        }
    }

    pub fn payload_length(&self) -> u8 {
        let auth_type = AuthType::from_u8(self.auth_type());
        match auth_type {
            AuthType::None => unsafe { u8::from_be_bytes([*self.slice.as_ptr().add(9)]) },
            _ => unsafe { u8::from_be_bytes([*self.slice.as_ptr().add(25)]) },
        }
    }

    pub fn to_header(&self) -> IpmiV1Header {
        let auth_type = AuthType::from_u8(self.auth_type());
        IpmiV1Header {
            auth_type: auth_type,
            session_seq_number: self.session_seq_number(),
            session_id: self.session_id(),
            auth_code: {
                // if let auth_type = AuthType::None {}
                match AuthType::from_u8(self.auth_type()) {
                    AuthType::None => 0x00,
                    _ => self.auth_code(),
                }
            },
            payload_length: self.payload_length(),
        }
    }
}
