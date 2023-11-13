mod commands;

use bitvec::prelude::*;

#[derive(Debug)]
pub struct IpmiPayload1_5 {
    pub rs_addr: u8,
    pub net_fn: u8,
    pub rs_lun: u8,
    pub rq_addr: u8,
    pub rq_seq: u8,
    pub rq_lun: u8,
    pub cmd: u8,
    pub completion_code: u8,
    pub data: Vec<u8>,
}

impl IpmiPayload1_5 {
    fn get8bit_checksum(byte_array: &[u8]) -> u8 {
        let answer: u8 = byte_array.iter().fold(0, |a, &b| a.wrapping_add(b));
        255 - answer + 1
    }

    fn join_bits_to_byte(long_bits: u8, short_bits: u8) -> u8 {
        let mut bv: BitVec<u8, Msb0> = bitvec![u8, Msb0; 0;8];
        bv[0..6].store::<u8>(long_bits);
        bv[6..].store::<u8>(short_bits);
        let result = bv[..].load::<u8>();
        result
    }

    fn to_be_endian(byte_array: &Vec<u8>) -> Vec<u8> {
        let mut new: Vec<u8> = byte_array.clone();
        new.sort();
        new.reverse();
        new
    }

    pub fn from_slice(bytes: &[u8]) -> IpmiPayload1_5 {
        let netfn_rqlun: &BitSlice<u8, Msb0> = BitSlice::<u8, Msb0>::from_element(&bytes[1]);
        let (netfn_slice, rqlun_slice) = (&netfn_rqlun[0..6], &netfn_rqlun[7..8]);
        let netfn = netfn_slice[..].load::<u8>();
        let rqlun = rqlun_slice[..].load::<u8>();

        let rqseq_rslun: &BitSlice<u8, Msb0> = BitSlice::<u8, Msb0>::from_element(&bytes[1]);
        let (rqseq_slice, rslun_slice) = (&rqseq_rslun[0..6], &rqseq_rslun[7..8]);
        let rqseq = rqseq_slice[..].load::<u8>();
        let rslun = rslun_slice[..].load::<u8>();
        let data: Vec<u8> = Vec::from(&bytes[7..bytes.len() - 1]);
        IpmiPayload1_5 {
            rs_addr: bytes[3],
            net_fn: netfn,
            rs_lun: rslun,
            rq_addr: bytes[0],
            rq_seq: rqseq,
            rq_lun: rqlun,
            cmd: bytes[5],
            completion_code: bytes[6],
            data: data,
        }
    }

    pub fn get_bytes(&self) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];
        let netfn_rslun = Self::join_bits_to_byte(self.net_fn, self.rs_lun);
        let rqseq_rqlun = Self::join_bits_to_byte(self.rq_seq, self.rq_lun);
        let be_data = Self::to_be_endian(&self.data);
        result.push(self.rs_addr);
        result.push(netfn_rslun);
        result.push(Self::get8bit_checksum(&vec![self.rs_addr, netfn_rslun]));
        result.push(self.rq_addr);
        result.push(rqseq_rqlun);
        result.push(self.cmd);
        for &byte in be_data.iter() {
            result.push(byte);
        }
        result.push(Self::get8bit_checksum(&result[3..]));
        result
    }
}
