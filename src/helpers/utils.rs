use bitvec::prelude::*;
pub fn join_two_bits_to_byte(first: u8, second: u8, split_index: usize) -> u8 {
    let mut bv: BitVec<u8, Msb0> = bitvec![u8, Msb0; 0;8];
    bv[..split_index].store::<u8>(first);
    bv[split_index..].store::<u8>(second);
    bv[..].load::<u8>()
}
