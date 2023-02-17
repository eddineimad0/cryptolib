use super::des::{des_decrypt, des_encrypt};

pub fn triple_des_encrypt(plain_text: u64, key_1: u64, key_2: u64, key_3: u64) -> u64 {
    let mut cipher = des_encrypt(plain_text, key_1);
    cipher = des_decrypt(cipher, key_2);
    return des_encrypt(cipher, key_3);
}

pub fn triple_des_decrypt(plain_text: u64, key_1: u64, key_2: u64, key_3: u64) -> u64 {
    let mut cipher = des_decrypt(plain_text, key_3);
    cipher = des_encrypt(cipher, key_2);
    return des_decrypt(cipher, key_1);
}
