use aes::cipher::{BlockEncryptMut, KeyIvInit};
use bitvec::prelude::*;
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub fn join_two_bits_to_byte(first: u8, second: u8, split_index: usize) -> u8 {
    let mut bv: BitVec<u8, Msb0> = bitvec![u8, Msb0; 0;8];
    bv[..split_index].store::<u8>(first);
    bv[split_index..].store::<u8>(second);
    bv[..].load::<u8>()
}

pub fn pad_payload_bytes(data: &mut Vec<u8>) -> Vec<u8> {
    let length = &data.len();
    if length < &16 {
        let padding_needed = 16 - length;
        for i in 1..padding_needed {
            data.push(i.try_into().unwrap());
        }
        data.push((padding_needed - 1).try_into().unwrap());
        data.to_vec()
    } else if length % 16 == 0 {
        data.to_vec()
    } else {
        let padding_needed = length % 16;
        for i in 1..padding_needed {
            data.push(i.try_into().unwrap());
        }
        data.push((padding_needed - 1).try_into().unwrap());
        data.to_vec()
    }
}

pub fn aes_128_cbc_encrypt(key: [u8; 16], mut payload_bytes: Vec<u8>) -> Vec<u8> {
    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
    let mut iv = [0; 16];
    for i in 0..iv.len() {
        iv[i] = rand::random::<u8>();
    }

    let binding = pad_payload_bytes(&mut payload_bytes);
    let plaintext = binding.as_slice();

    // encrypt in-place
    // buffer must be big enough for padded plaintext
    let mut buf = [0u8; 48];
    let pt_len = plaintext.len();
    buf[..pt_len].copy_from_slice(&plaintext);
    let ct = Aes128CbcEnc::new(&key.into(), &iv.into())
        .encrypt_padded_mut::<aes::cipher::block_padding::NoPadding>(&mut buf, pt_len)
        .unwrap();
    ct.to_vec()
}

pub fn hash_hmac_sha_256(key: Vec<u8>, data: Vec<u8>) -> [u8; 32] {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac =
        HmacSha256::new_from_slice(key.as_slice()).expect("HMAC can take key of any size");
    mac.update(data.as_slice());
    let result = mac.finalize();
    let mut vec_bytes = [0; 32];
    let mut index = 0;
    for i in result.into_bytes() {
        vec_bytes[index] = i;
        index += 1;
    }
    vec_bytes
}
// pub fn encrypt_payload(key: [u8; 16], mut payload_bytes: Vec<u8>) -> Vec<u8> {
//     type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
//     // type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
//     // type Aes128Cbc = Cbc<Aes128, Pkcs7>;

//     // let test_packet = IpmiPayloadRawRequest::new(
//     //     NetFn::App,
//     //     Command::SetSessionPrivilegeLevel,
//     //     Some(vec![0x04]),
//     // )
//     // .create_packet(&self, 0x0200a800, 0x0000000a);

//     // let key = [0x42; 16];
//     // let key = [
//     //     0x79, 0x8f, 0xe6, 0x1d, 0x60, 0xf5, 0x26, 0xda, 0xea, 0xab, 0x52, 0x6d, 0x1e, 0x34, 0xf5,
//     //     0x77,
//     // ];
//     // let iv = [0x24; 16];
//     let iv = [rand::random::<u8>(); 16];
//     println!("{:x?}", iv);

//     // println!("test packet whole: {:x?}", &test_packet.payload.clone());
//     // let mut binding = test_packet.payload.clone().unwrap().to_bytes();
//     // let binding = pad_payload_bytes(&mut binding);
//     let binding = pad_payload_bytes(&mut payload_bytes);
//     let plaintext = binding.as_slice();
//     // let plaintext = binding.as_slice();
//     // let plaintext = [
//     //     0x20, 0x18, 0xc8, 0x81, 0x20, 0x3b, 0x4, 0x20, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
//     //     0x07, 0x07,
//     // ]
//     // .as_slice();
//     // println!("test packet: {:x?}", &plaintext);
//     // if let x = test_packet.payload.unwrap() {
//     //     plaintext = x.to_bytes();
//     // };
//     // let plaintext = [
//     //     0x06, 0xc0, 0x00, 0x8b, 0x00, 0x02, 0x0a, 0x00, 0x00, 0x00, 0x20, 0x00, 0xad, 0xf9,
//     //     0x95, 0x36, 0x64, 0x35, 0x8f, 0xcc, 0xec, 0x45, 0x9a, 0x4c, 0xbd, 0x7e, 0xee, 0x39,
//     //     0x7e, 0x6a, 0x27, 0x7a, 0x5a, 0xb8, 0xc2, 0x8d, 0x75, 0x67, 0x4a, 0x6c, 0x93, 0x67,
//     //     0xa0, 0xae, 0xff, 0xff, 0x02, 0x07,
//     // ];
//     // let ciphertext = hex!(
//     //     "c7fe247ef97b21f07cbdd26cb5d346bf"
//     //     "d27867cb00d9486723e159978fb9a5f9"
//     //     "14cfb228a710de4171e396e7b6cf859e"
//     // );
//     // let cipher = Aes128Cbc::new_from_slices(&self.k2, &iv.as_slice()).unwrap();

//     // let pos = plaintext.len();

//     // let mut buffer = [0u8; 128];

//     // buffer[..pos].copy_from_slice(plaintext);

//     // let ciphertext = cipher.encrypt(&mut buffer, pos).unwrap();

//     // println!("\nCiphertext: {:?}", ciphertext);

//     // let cipher = Aes128Cbc::new_from_slices(&self.k2, &iv).unwrap();
//     // let mut buf = ciphertext.to_vec();
//     // let decrypted_ciphertext = cipher.decrypt(&mut buf).unwrap();

//     // println!("\nCiphertext: {:?}", decrypted_ciphertext);

//     // encrypt/decrypt in-place
//     // buffer must be big enough for padded plaintext
//     let mut buf = [0u8; 48];
//     // let test = GenericArray::from_slice(plaintext.as_slice());
//     // let array: &GenericArray<u8> = GenericArray::from_slice(plaintext.as_slice());
//     let pt_len = plaintext.len();
//     // let mut block = *Block::from_slice(plaintext);
//     // let mut block2 = *Block::from_slice([0; 16].as_slice());
//     buf[..pt_len].copy_from_slice(&plaintext);
//     // let key = self.k2[..16];
//     let ct = Aes128CbcEnc::new(&key.into(), &iv.into())
//         // .encrypt_block_b2b_mut(&mut block, &mut block2);
//         .encrypt_padded_mut::<aes::cipher::block_padding::NoPadding>(&mut buf, pt_len)
//         .unwrap();
//     // .encrypt_block_mut(&mut buf.into());
//     // println!("out buf: {:x?}", block2);
//     ct.to_vec()
//     // println!("ct {:x?}", ct);
//     // assert_eq!(ct, &ciphertext[..]);

//     // let pt = Aes256CbcDec::new(&self.k2.into(), &iv.into())
//     //     .decrypt_padded_mut::<Pkcs7>(&mut buf)
//     //     .unwrap();
//     // println!("plain text {:x?}", pt)
//     // assert_eq!(pt, &plaintext);
// }
