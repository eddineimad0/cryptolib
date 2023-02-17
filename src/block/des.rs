// DES steps for each 64 block of plaintext
/*    initial plain block permutation (optional).
*     Key Transformation :
*        # reduce to 56-bit by ignoring every 8-bit.
*    16-rounds for each round :
*        # extract a 48-bit subkey for the 56-bit key by:
*            divide 56-bit key into 2 28-bit havles circularly shift the halfs by Round shift number
*            apply a compression permutation to extract the 48-bit out of the 56-bit
*        # the plain block is divided into 2 32-bit halves the right one is the:
*           1) passed through an expansion permutation to expand its size to 48-bit.
*           2) xored with the round subkey.
*           3) the 48-bit result is divided into 8 6-bit blocks each is substitued by a corresponding s-box.
*           4) the output of each s-box is 4-bit for an output of 32-bit block that is then permuted by the P-box.
*           5) the output of the Pbox is xored with the initial left half of the plain block to create the
*              new right block
*           6) the original right block becomes the left block for the next round.
*        # at the end of the 16-rounds the inverse of the initial plain block permutation is applied (optional)
*/

// Permutations

const REDUC_PERM: [u8; 56] = [
    56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59,
    51, 43, 35, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 60, 52, 44, 36, 28,
    20, 12, 4, 27, 19, 11, 3,
];

const INIT_PERM: [u8; 64] = [
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63,
    55, 47, 39, 31, 23, 15, 7, 56, 48, 40, 32, 24, 16, 8, 0, 58, 50, 42, 34, 26, 18, 10, 2, 60, 52,
    44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
];

const FINAL_PERM: [u8; 64] = [
    39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25, 32, 0, 40, 8, 48, 16, 56, 24,
];

const COMP_PERM: [u8; 48] = [
    13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9, 22, 18, 11, 3, 25, 7, 15, 6, 26, 19, 12, 1, 40, 51,
    30, 36, 46, 54, 29, 39, 50, 44, 32, 47, 43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31,
];

const EXPANSION_PERM: [u8; 48] = [
    31, 0, 1, 2, 3, 4, 3, 4, 5, 6, 7, 8, 7, 8, 9, 10, 11, 12, 11, 12, 13, 14, 15, 16, 15, 16, 17,
    18, 19, 20, 19, 20, 21, 22, 23, 24, 23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31, 0,
];

const P_BOX_PERM: [u8; 32] = [
    15, 6, 19, 20, 28, 11, 27, 16, 0, 14, 22, 25, 4, 17, 30, 9, 1, 7, 23, 13, 31, 26, 2, 8, 18, 12,
    29, 5, 21, 10, 3, 24,
];

const ROT: [u8; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

const S_BOX: [[u8; 64]; 8] = [
    [
        /* S1 */
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12,
        11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9,
        1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
    ],
    [
        /* S2 */
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1,
        10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15,
        4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    ],
    [
        /* S3 */
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14,
        12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8,
        7, 4, 15, 14, 3, 11, 5, 2, 12,
    ],
    [
        /* S4 */
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2,
        12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1,
        13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
    ],
    [
        /* S5 */
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15,
        10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14,
        2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
    ],
    [
        /* S6 */
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13,
        14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5,
        15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    ],
    [
        /* S7 */
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5,
        12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4,
        10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
    ],
    [
        /* S8 */
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6,
        11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10,
        8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
    ],
];

/// Masks for extracticting the MSB of 32 and 64 bit number.
const BIT0_64MASK: u64 = 0x8000000000000000_u64;
const BIT0_32MASK: u32 = 0x80000000_u32;

//////////////////////////////////////////////////////////////////////
/// Sets a bit in in `to` at a given position `to_pos` depending
/// on bit in `from` at position `to_pos`.
//////////////////////////////////////////////////////////////////////
fn permute_bit64(from: &u64, to: &mut u64, from_pos: u8, to_pos: u8) {
    if ((*from << from_pos) & BIT0_64MASK) != 0 {
        *to |= BIT0_64MASK >> to_pos;
    }
}

//////////////////////////////////////////////////////////////////////
/// Sets a bit in in `to` at a given position `to_pos` depending
/// on bit in `from` at position `to_pos`.
//////////////////////////////////////////////////////////////////////
fn permute_bit32(from: &u32, to: &mut u32, from_pos: u8, to_pos: u8) {
    if ((from << from_pos) & BIT0_32MASK) != 0 {
        *to |= BIT0_32MASK >> to_pos;
    }
}

//////////////////////////////////////////////////////////////////////
/// Applies the Initial Permutation to the given 64 bits
/// plain_text block `pt_block`, and returns the result of the permutation.
//////////////////////////////////////////////////////////////////////
fn init_permutation(pt_block: u64) -> u64 {
    let mut perm_block: u64 = 0;
    let mut i = 0;
    while i < 64 {
        permute_bit64(&pt_block, &mut perm_block, INIT_PERM[i], i as u8);
        i += 1;
    }
    return perm_block;
}

//////////////////////////////////////////////////////////////////////
/// Applies the Final Permutation to the given 64 bits
/// cipher_text block `ct_block`, and returns the result of the permutation.
//////////////////////////////////////////////////////////////////////
fn final_permutation(ct_block: u64) -> u64 {
    let mut perm_block: u64 = 0;
    let mut i = 0;
    while i < 64 {
        permute_bit64(&ct_block, &mut perm_block, FINAL_PERM[i], i as u8);
        i += 1;
    }
    return perm_block;
}

/////////////////////////////////////////////////////////////////////
/// Returns a 32 bits plain_text halve after performing a circular
/// left rotation on it according to the `shift` parameter.
///
/// For simple example a circular left rotation of the binary string
/// 100111 by 2 produces the bit string 011110.
////////////////////////////////////////////////////////////////////
fn circ_rot_left(mut halve: u32, shift: u8) -> u32 {
    let temp: u32 = halve >> (28 - shift);
    halve <<= shift;
    halve &= 0x0FFFFFFF_u32;
    return halve + temp;
}

/////////////////////////////////////////////////////////////////////
/// Returns an array of the 16 rounds keys computed form the given
/// `key`.
////////////////////////////////////////////////////////////////////
fn prepare_key(key: u64) -> [u64; 16] {
    // key reduction.
    let mut redu_key: u64 = 0;
    let mut i = 0;
    while i < 56 {
        permute_bit64(&key, &mut redu_key, REDUC_PERM[i], i as u8);
        i += 1;
    }
    let mut l_hlv: u32 = (redu_key >> 36) as u32; // left halve contains the first 28 bits.
    let mut r_hlv: u32 = ((redu_key >> 8) & 0x0FFFFFFF) as u32; // right halve contains the last 28 bits

    let mut round = 0;
    let mut keys: [u64; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut next_key: u64;
    let mut round_key;
    while round < 16 {
        // circular rotation.
        l_hlv = circ_rot_left(l_hlv, ROT[round as usize]);
        r_hlv = circ_rot_left(r_hlv, ROT[round as usize]);
        // combine the 2 halves
        next_key = ((l_hlv as u64) << 36) | ((r_hlv as u64) << 8);
        // apply a compression permutation to extract the 48-bit out of the 56-bit.
        i = 0;
        round_key = 0;
        while i < 48 {
            permute_bit64(&next_key, &mut round_key, COMP_PERM[i], i as u8);
            i += 1;
        }
        keys[round] = round_key;
        round += 1;
    }
    return keys;
}

////////////////////////////////////////////////////////////////////////////////
/// Returns the result of applying the des function to the given `r_block`.
///
/// A DES round includes the following operations,
/// that combines to make the des function:
/// 1. Expand the `r_block` to 48 bits using expansion permutation.
/// 2. Xor the expanded r_block with the `round_key`.
/// 3. Apply the S-Boxes on the result of the xor.
/// 4. Perform P-Box permutation on the result.
/// 5. Finally xor `l_block` with the output of the P-Box permutation.
///////////////////////////////////////////////////////////////////////////////
fn des_round(l_block: u32, r_block: u32, round_key: u64) -> u32 {
    // expansion permutation to expand its size to 48-bit.
    let mut exp_block = 0;
    let temp_block: u64 = (r_block as u64) << 32;
    let mut i = 0;
    while i < 48 {
        permute_bit64(&temp_block, &mut exp_block, EXPANSION_PERM[i], i as u8);
        i += 1;
    }
    // xored with the round subkey.
    exp_block = exp_block ^ round_key;
    // S-Boxes
    let mut row;
    let mut col;
    let mut s_out: u32 = 0;
    i = 0;
    let mut j = 1;
    while i < 8 {
        row = if ((exp_block << (6 * i)) & BIT0_64MASK) == BIT0_64MASK {
            2 // Bit 0 of the current 6 bits is set(1).
        } else {
            0 // Bit 0 of the current 6 bits is clear (0).
        };
        if ((exp_block << (6 * i + 5)) & BIT0_64MASK) == BIT0_64MASK {
            row += 1; // bit 5 is set.
        };

        col = 0;
        while j < 5 {
            if ((exp_block << (6 * i + j)) & BIT0_64MASK) == BIT0_64MASK {
                col |= 1 << (4 - j);
            }
            j += 1;
        }
        j = 1;
        s_out |= (S_BOX[i][(row * 16 + col)] as u32) << (28 - (4 * i));
        i += 1;
    }
    // P Box
    i = 0;
    let mut r_temp_block: u32 = 0;
    while i < 32 {
        permute_bit32(&s_out, &mut r_temp_block, P_BOX_PERM[i], i as u8);
        i += 1;
    }
    //xored with the initial left half.
    return r_temp_block ^ l_block;
}

////////////////////////////////////////////////////////////////////////
/// Returns the encrypted 64-bit block.
///////////////////////////////////////////////////////////////////////
pub fn des_encrypt(plain_text: u64, key: u64) -> u64 {
    // initial permutation.
    let plain_text = init_permutation(plain_text);
    // prepare keys for the rounds
    let round_key = prepare_key(key);
    // block spliting.
    let mut left: u32 = (plain_text >> 32) as u32;
    let mut right: u32 = (plain_text & 0xFFFFFFFF_u64) as u32;
    let mut temp_right = right;
    let mut i = 0;
    while i < 16 {
        right = des_round(left, right, round_key[i]);
        left = temp_right;
        temp_right = right;
        i += 1;
    }

    // combine the 2 halves (R16L16) and apply the final permutation
    let cipher_text = ((right as u64) << 32) + (left as u64);
    return final_permutation(cipher_text);
}

////////////////////////////////////////////////////////////////////////
/// Returns the decrypted 64-bit block.
///////////////////////////////////////////////////////////////////////
pub fn des_decrypt(cipher_text: u64, key: u64) -> u64 {
    let cipher_text = init_permutation(cipher_text);
    let round_key = prepare_key(key);
    // block spliting.
    let mut left: u32 = (cipher_text >> 32) as u32;
    let mut right: u32 = (cipher_text & 0xFFFFFFFF_u64) as u32;
    let mut temp_right = right;
    let mut i = 0;
    while i < 16 {
        right = des_round(left, right, round_key[15 - i]);
        left = temp_right;
        temp_right = right;
        i += 1;
    }

    // combine the 2 halves (R16L16) and apply the final permutation
    let cipher_text = ((right as u64) << 32) + (left as u64);
    return final_permutation(cipher_text);
}

#[cfg(test)]
mod tests {
    /*   Validation Sets:
     *    #1
     *    Key    : 0123 4567 89ab cdef
     *    Plain  : 0123 4567 89ab cdef
     *    Cipher : c957 4425 6a5e d31d
     *
     *    #2
     *    Key    : 0123 4567 89ab cdef
     *    Plain  : 0123 4567 89ab cde7
     *    Cipher : c957 4425 6a5e d31d
     */
    use super::*;

    #[test]
    fn test_des_comp() {
        let block: u64 = 0x123456789ABCDEF;
        let perm_block = init_permutation(block);
        assert_eq!(final_permutation(perm_block), block);
        // Rotation
        assert_eq!(circ_rot_left(15, 2), 60);
    }

    #[test]
    fn test_des_encrypt() {
        // # 1st set.
        let mut plain = 0x0123456789ABCDEF;
        let mut key = 0x0123456789ABCDEF;
        assert_eq!(des_encrypt(plain, key), 0x56CC09E7CFDC4CEF);
        // # 2nd set.
        plain = 0x123456789ABCDE7;
        key = 0x123456789ABCDEF;
        assert_eq!(des_encrypt(plain, key), 0xC95744256A5ED31D);
    }

    #[test]
    fn test_des_decrypt() {
        // # 1st set.
        let mut cipher = 0x56CC09E7CFDC4CEF;
        let mut key = 0x0123456789ABCDEF;
        assert_eq!(des_decrypt(cipher, key), 0x0123456789ABCDEF);
        // # 2nd set.
        cipher = 0xC95744256A5ED31D;
        key = 0x123456789ABCDEF;
        assert_eq!(des_decrypt(cipher, key), 0x123456789ABCDE7);
    }
}
