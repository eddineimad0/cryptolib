//#####################################################################################o
// Base64 is a group of binary-to-text encoding schemes                                |
// that represent binary data (more specifically, a sequence of 8-bit bytes)           |
// in sequences of 24 bits that can be represented by four 6-bit Base64 digits.        |
// Base64 is also widely used for sending e-mail attachments.                          | 
// This is required because SMTP – in its original form – was designed                 |
// to transport 7-bit ASCII characters only. This encoding causes                      |
// an overhead of 33–37% (33% by the encoding itself; up to 4% more by                 |
// the inserted line breaks "CRLF").                                                   |
//                                                                                     | 
// @Refrences:                                                                         |
// RFC 2045: https://datatracker.ietf.org/doc/html/rfc2045                             |
// RFC 4648§4: https://datatracker.ietf.org/doc/html/rfc4648#section-4                 |
// RFC 4648§5: https://datatracker.ietf.org/doc/html/rfc4648#section-5                 |
//#####################################################################################o

// Base64 table(RFC 4648§4) padding '=' included as the 65th byte.
const B64_TABLE:&[u8;65] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
// A URL safe version(RFC 4648§5).
const B64_URL_TABLE:&[u8;65] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=";

// ASCII to Base64(6 bits) mapping
const B64_INDEX: [u8; 256] = [
    /* nul, soh, stx, etx, eot, enq, ack, bel, */
         0,   0,   0,   0,   0,   0,   0,   0,

    /*  bs, tab,  lf,  vt,  ff,  cr,  so,  si, */
         0,   0,   0,   0,   0,   0,   0,   0,

    /* dle, dc1, dc2, dc3, dc4, nak, syn, etb, */
         0,   0,   0,   0,   0,   0,   0,   0,

    /* can,  em, sub, esc,  fs,  gs,  rs,  us, */
         0,   0,   0,   0,   0,   0,   0,   0,

    /*  sp, '!', '"', '#', '$', '%', '&', ''', */
         0,   0,   0,   0,   0,   0,   0,   0,

    /* '(', ')', '*', '+', ',', '-', '.', '/', */
         0,   0,   0,  62,   0,   62,   0,  63,

    /* '0', '1', '2', '3', '4', '5', '6', '7', */
        52,  53,  54,  55,  56,  57,  58,  59,

    /* '8', '9', ':', ';', '<', '=', '>', '?', */
        60,  61,   0,   0,   0,   0,   0,   0,

    /* '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', */
         0,   0,   1,   2,   3,   4,   5,   6,

    /* 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', */
         7,   8,   9,  10,  11,  12,  13,  14,

    /* 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', */
        15,  16,  17,  18,  19,  20,  21,  22,

    /* 'X', 'Y', 'Z', '[', '\', ']', '^', '_', */
        23,  24,  25,   0,   0,   0,   0,   63,
  
    /* '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', */
         0,  26,  27,  28,  29,  30,  31,  32,

    /* 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', */
        33,  34,  35,  36,  37,  38,  39,  40,

    /* 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', */
        41,  42,  43,  44,  45,  46,  47,  48,

    /* 'x', 'y', 'z', '{', '|', '}', '~', del, */
        49,  50,  51,   0,   0,   0,   0,   0,

    /*           Extended ASCII Codes          */
         0,   0,   0,   0,   0,   0,   0,   0,

         0,   0,   0,   0,   0,   0,   0,   0,

         0,   0,   0,   0,   0,   0,   0,   0,

         0,   0,   0,   0,   0,   0,   0,   0,

         0,   0,   0,   0,   0,   0,   0,   0,
         
         0,   0,   0,   0,   0,   0,   0,   0,

         0,   0,   0,   0,   0,   0,   0,   0,

         0,   0,   0,   0,   0,   0,   0,   0,

         0,   0,   0,   0,   0,   0,   0,   0,

         0,   0,   0,   0,   0,   0,   0,   0,

         0,   0,   0,   0,   0,   0,   0,   0,

         0,   0,   0,   0,   0,   0,   0,   0,

         0,   0,   0,   0,   0,   0,   0,   0,

         0,   0,   0,   0,   0,   0,   0,   0,

         0,   0,   0,   0,   0,   0,   0,   0,

         0,   0,   0,   0,   0,   0,   0,   0,
         ];
/////////////////////////////////////////////////////////////////////////////////
///Encode a sequence of bytes into a standard(RFC 4648) base64 sequence.
///# Arguments 
///* `data`: A refrence to the sequence of bytes to be encoded.
///* `no_padding`: If set to true the returned sequence won't contain any padding('=').
///* `url_safe`: If set true the returned sequence URL and filename safe (uses '-','_' instead of '+','/').
///# Return
/// A vector containing the base64 encrypted data.
////////////////////////////////////////////////////////////////////////////////
pub fn b64_encode(data: &[u8],no_padding:bool,url_safe:bool) -> Vec<u8> {
    let table = match url_safe {
        true => &B64_URL_TABLE,
        false => &B64_TABLE,
    };
    let data_len = data.len();
    let output_len = 4 * ((data_len + 2) / 3); // 3-byte blocks to 4-bytes.
    let mut b_enc = 0; // Number of bytes encoded.
    let mut index: u8;
    let mut enc_data = Vec::<u8>::with_capacity(output_len);
    while (data_len - b_enc) >= 3 {
        index = data[b_enc] >> 2;
        enc_data.push(table[index as usize] as u8);
        index = ((data[b_enc] & 0x03) * 16) | (data[b_enc + 1] >> 4);   //'<< 4' replaced by '*16'
        enc_data.push(table[index as usize] as u8);
        index = ((data[b_enc + 1] & 0x0F) * 4) | (data[b_enc + 2] >> 6); //'<< 2' replaced by '*4'
        enc_data.push(table[index as usize] as u8);
        index = data[b_enc + 2] & 0x3F;
        enc_data.push(table[index as usize] as u8);
        b_enc += 3;
    }
    if (data_len - b_enc) > 0 {
        index = data[b_enc] >> 2;
        enc_data.push(table[index as usize] as u8);
        if (data_len - b_enc) == 1 {
            index = (data[b_enc] & 0x03) * 16;
            enc_data.push(table[index as usize] as u8);
            if !no_padding
            {
                enc_data.push(table[64] as u8); // Add padding '='.
            }
        } else {
            index = ((data[b_enc] & 0x03) * 16 ) | (data[b_enc + 1] >> 4);
            enc_data.push(table[index as usize] as u8);
            index = (data[b_enc + 1] & 0x0F) * 4;
            enc_data.push(table[index as usize] as u8);
        }
        if !no_padding
        {
            enc_data.push(table[64] as u8); // Add padding '='.
        }
    }
    return enc_data;
}

/////////////////////////////////////////////////////////////////////////////////
///Encode a sequence of bytes into a MIME(RFC 2045) base64 sequence.
///# Arguments 
///* `data`: A refrence to the sequence of bytes to be encoded.
///# Return
/// A vector containing the base64 encrypted data.
////////////////////////////////////////////////////////////////////////////////
pub fn b64_mime_encode(data:&[u8])->Vec<u8>
{
    let mut enc_data = b64_encode(&data, false, false);    

    //loop and insert line break
    let data_len = enc_data.len();
    let mut index = 76;
    enc_data.reserve_exact(data_len + 2*(data_len % 76));
    while index < data_len {
        enc_data.insert(index, 0x0D );
        enc_data.insert(index + 1, 0x0A);
        index += 76 + 1;
    }
    return enc_data;

}

////////////////////////////////////////////////////////////////////////////////////////////////////////
///Decode a base64(RFC 4648) sequence of data.
///# Arguments
///* `enc_data`: A refrence to the base64 sequence.
///# Return 
/// Some vector containing the decrypted data or None if the `enc_data` is empty.
///# Note
/// ''' 
/// The function doesn't perform any checks on the enc_data, and expect an RFC 4648
/// compliant(standard or url) sequence and for malformed inputs the function returns a malformed outputs.
/// '''
///////////////////////////////////////////////////////////////////////////////////////////////////////
pub fn b64_decode(enc_data:&Vec<u8>) -> Option<Vec<u8>>
{
    let data_len = enc_data.len();
    if data_len == 0{
        return None;
    }
    let data_mod = data_len % 4;
    let pad1 = (data_mod != 0) || (enc_data[data_len - 1] == B64_TABLE[64]);
    let pad2 = pad1 && (data_mod > 2 || ((data_mod==0) && enc_data[data_len - 2] != B64_TABLE[64])); // true if there only 1 padding(the last segment contain only 2 bytes of data).
    let last_index = ((data_len - (pad1 as usize)) >> 2 ) * 4;
    // output length is approx ((encoded_len + 3) /4 * 3) in case the encoded data has no padding.
    let mut dec_data = Vec::<u8>::with_capacity(((data_len + 3) >> 2) * 3);
    let mut b_dec = 0; // Number of data decrypted.
    let mut buff: i32;
    while b_dec < last_index {
        buff = (B64_INDEX[enc_data[b_dec] as usize] as i32) << 18
            | (B64_INDEX[enc_data[b_dec + 1] as usize] as i32) << 12
            | (B64_INDEX[enc_data[b_dec + 2] as usize] as i32) << 6
            | (B64_INDEX[enc_data[b_dec + 3] as usize] as i32);
        dec_data.push((buff >> 16) as u8);
        dec_data.push(((buff >> 8) & 0xFF) as u8);
        dec_data.push((buff & 0xFF) as u8);
        b_dec += 4;
    }
    if pad1 {
        buff = (B64_INDEX[enc_data[last_index] as usize] as i32) << 18
            | (B64_INDEX[enc_data[last_index + 1] as usize] as i32) << 12;
        dec_data.push((buff >> 16) as u8);
        if pad2 {
            buff |= (B64_INDEX[enc_data[last_index + 2] as usize] as i32) << 6;
            dec_data.push(((buff >> 8) & 0xFF) as u8);
        }
    }
    dec_data.shrink_to_fit();
    return Some(dec_data);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////
///Decode a MIME base64(RFC 2045) sequence of data.
///# Arguments
///* `enc_data`: A refrence to the base64 sequence.
///# Return 
/// Some vector containing the decrypted data or None if `enc_data` is empty.
///# Note
/// ''' 
/// The function doesn't perform any checks on the `enc_data`,
/// for malformed inputs the function returns a malformed outputs.
/// '''
///////////////////////////////////////////////////////////////////////////////////////////////////////
pub fn b64_mime_decode(enc_data:&[u8])->Option<Vec<u8>>
{
    // Remove CRLF sequences from the data.
    let f_enc_data = enc_data.iter().filter(|&val|(*val != 0x0D && *val != 0x0A)).collect::<Vec<_>>();

    let data_len = f_enc_data.len();
    if data_len == 0{
        return None;
    }
    let data_mod = data_len % 4;
    let pad1 = (data_mod != 0) || (*f_enc_data[data_len - 1] == B64_TABLE[64]);
    let pad2 = pad1 && (data_mod > 2 || ((data_mod==0) && *f_enc_data[data_len - 2] != B64_TABLE[64])); // true if there only 1 padding(the last segment contain only 2 bytes of data).
    let last_index = ((data_len - (pad1 as usize)) >> 2 ) * 4;
    // output length is approx ((encoded_len + 3) /4 * 3) in case the encoded data has no padding.
    let mut dec_data = Vec::<u8>::with_capacity(((data_len + 3) >> 2)*3);
    let mut b_dec = 0; // Number of data decrypted.
    let mut buff: i32;
    while b_dec < last_index {
        buff = (B64_INDEX[*f_enc_data[b_dec] as usize] as i32) << 18
            | (B64_INDEX[*f_enc_data[b_dec + 1] as usize] as i32) << 12
            | (B64_INDEX[*f_enc_data[b_dec + 2] as usize] as i32) << 6
            | (B64_INDEX[*f_enc_data[b_dec + 3] as usize] as i32);
        dec_data.push((buff >> 16) as u8);
        dec_data.push(((buff >> 8) & 0xFF) as u8);
        dec_data.push((buff & 0xFF) as u8);
        b_dec += 4;
    }
    if pad1 {
        buff = (B64_INDEX[*f_enc_data[last_index] as usize] as i32) << 18
            | (B64_INDEX[*f_enc_data[last_index + 1] as usize] as i32) << 12;
        dec_data.push((buff >> 16) as u8);
        if pad2 {
            buff |= (B64_INDEX[*f_enc_data[last_index + 2] as usize] as i32) << 6;
            dec_data.push(((buff >> 8) & 0xFF) as u8);
        }
    }
    dec_data.shrink_to_fit();
    return Some(dec_data);
}

#[cfg(test)]
mod tests
{
    use super::*;
    #[test]
    fn basic_test()
    {
        assert_eq!(b64_encode(&b"abcd".to_vec(),false,false),b"YWJjZA==".to_vec());
        assert_eq!(
            b64_encode(&b"\x9f\x0e8\xbc\xf5\xd0-\xb4.\xd4\xf0?\x8f\xe7\t{.\xff/6\xcbTY!\xae9\x82".to_vec(),false,false),
            b"nw44vPXQLbQu1PA/j+cJey7/LzbLVFkhrjmC".to_vec()
        );
        assert_eq!(b64_encode(&b"\x7f3\x15\x1a\xd3\xf91\x9bS\xa44=".to_vec(),false,false), b"fzMVGtP5MZtTpDQ9".to_vec());
        assert_eq!(
            b64_encode(&b"7:\xf5\xd1[\xbfV/P\x18\x03\x00\xdc\xcd\xa1\xecG".to_vec(),false,false),
            b"Nzr10Vu/Vi9QGAMA3M2h7Ec=".to_vec()
        );
        assert_eq!(
            b64_encode(&b"\xc3\xc9\x18={\xc4\x08\x97wN\xda\x81\x84?\x94\xe6\x9e".to_vec(),false,false),
            b"w8kYPXvECJd3TtqBhD+U5p4=".to_vec()
        );
        assert_eq!(
            b64_encode(&b"\x8cJ\xf8e\x13\r\x8fw\xa8\xe6G\xce\x93c*\xe7M\xb6\xd7".to_vec(),false,false),
            b"jEr4ZRMNj3eo5kfOk2Mq50221w==".to_vec()
        );
        assert_eq!(
            b64_encode(&b"\xde\xc4~\xb2}\xb1\x14F.~\xa1z|s\x90\x8dd\x9b\x04\x81\xf2\x92{".to_vec(),false,true),
            b"3sR-sn2xFEYufqF6fHOQjWSbBIHykns=".to_vec()
        );
        assert_eq!(
            b64_encode(&b"\xf0y\t\x14\xd161n\x03e\xed\x0e\x05\xdf\xc1\xb9\xda".to_vec(),false,true),
            b"8HkJFNE2MW4DZe0OBd_Budo=".to_vec()
        );
        assert_eq!(
            b64_encode(&b"*.\x8e\x1d@\x1ac\xdd;\x9a\xcc \x0c\xc2KI".to_vec(),false,false),
            b"Ki6OHUAaY907mswgDMJLSQ==".to_vec()
        );
        assert_eq!(b64_encode(&b"\xd6\x829\x82\xbc\x00\xc9\xfe\x03".to_vec(),false,false), b"1oI5grwAyf4D".to_vec());
        assert_eq!(
            b64_encode(&b"\r\xf2\xb4\xd4\xa1g\x8fhl\xaa@\x98\x00\xda\x95".to_vec(),false,false),
            b"DfK01KFnj2hsqkCYANqV".to_vec()
        );
        assert_eq!(
            b64_encode(&b"\x1a\xfaV\x1a\xc2e\xc0\xad\xef|\x07\xcf\xa9\xb7O".to_vec(),false,false),
            b"GvpWGsJlwK3vfAfPqbdP".to_vec()
        );
        assert_eq!(b64_encode(&b"\xc20{_\x81\xac".to_vec(),false,true), b"wjB7X4Gs".to_vec());
        assert_eq!(
            b64_encode(&b"B\xa85\xac\xe9\x0ev-\x8bT\xb3|\xde".to_vec(),false,true),
            b"Qqg1rOkOdi2LVLN83g==".to_vec()
        );
        assert_eq!(
            b64_encode(&b"\x05\xe0\xeeSs\xfdY9\x0b7\x84\xfc-\xec".to_vec(),false,false),
            b"BeDuU3P9WTkLN4T8Lew=".to_vec()
        );
        assert_eq!(
            b64_encode(&b"Qj\x92\xfa?\xa5\xe3_[\xde\x82\x97{$\xb2\xf9\xd5\x98\x0cy\x15\xe4R\x8d".to_vec(),false,false),
            b"UWqS+j+l419b3oKXeySy+dWYDHkV5FKN".to_vec()
        );
        assert_eq!(b64_encode(&b"\x853\xe0\xc0\x1d\xc1".to_vec(),false,false), b"hTPgwB3B".to_vec());
        assert_eq!(b64_encode(&b"}2\xd0\x13m\x8d\x8f#\x9c\xf5,\xc7".to_vec(),false,false), b"fTLQE22NjyOc9SzH".to_vec());
    }

    #[test]
    fn b64_decode_test() {
        assert_eq!(
            b64_decode(&b"0zHJh0T+qrP/74wOb0Q=".to_vec()).unwrap(),
            b"\xd31\xc9\x87D\xfe\xaa\xb3\xff\xef\x8c\x0eoD".to_vec()
        );
        assert_eq!(
            b64_decode(&b"nw44vPXQLbQu1PA/j+cJey7/LzbLVFkhrjmC".to_vec()).unwrap(),
            b"\x9f\x0e8\xbc\xf5\xd0-\xb4.\xd4\xf0?\x8f\xe7\t{.\xff/6\xcbTY!\xae9\x82".to_vec()
        );
        assert_eq!(
            b64_decode(&b"fzMVGtP5MZtTpDQ9".to_vec()).unwrap(),
            b"\x7f3\x15\x1a\xd3\xf91\x9bS\xa44=".to_vec()
        );
        assert_eq!(
            b64_decode(&b"Nzr10Vu/Vi9QGAMA3M2h7Ec=".to_vec()).unwrap(),
            b"7:\xf5\xd1[\xbfV/P\x18\x03\x00\xdc\xcd\xa1\xecG".to_vec()
        );
        assert_eq!(
            b64_decode(&b"w8kYPXvECJd3TtqBhD+U5p4=".to_vec()).unwrap(),
            b"\xc3\xc9\x18={\xc4\x08\x97wN\xda\x81\x84?\x94\xe6\x9e".to_vec()
        );
        assert_eq!(
            b64_decode(&b"jEr4ZRMNj3eo5kfOk2Mq50221w==".to_vec()).unwrap(),
            b"\x8cJ\xf8e\x13\r\x8fw\xa8\xe6G\xce\x93c*\xe7M\xb6\xd7".to_vec()
        );
        assert_eq!(
            b64_decode(&b"3sR+sn2xFEYufqF6fHOQjWSbBIHykns=".to_vec()).unwrap(),
            b"\xde\xc4~\xb2}\xb1\x14F.~\xa1z|s\x90\x8dd\x9b\x04\x81\xf2\x92{".to_vec()
        );
        assert_eq!(
            b64_decode(&b"8HkJFNE2MW4DZe0OBd/Budo=".to_vec()).unwrap(),
            b"\xf0y\t\x14\xd161n\x03e\xed\x0e\x05\xdf\xc1\xb9\xda".to_vec()
        );
        assert_eq!(
            b64_decode(&b"Ki6OHUAaY907mswgDMJLSQ==".to_vec()).unwrap(),
            b"*.\x8e\x1d@\x1ac\xdd;\x9a\xcc \x0c\xc2KI".to_vec()
        );
        assert_eq!(
            b64_decode(&b"1oI5grwAyf4D".to_vec()).unwrap(),
            b"\xd6\x829\x82\xbc\x00\xc9\xfe\x03".to_vec()
        );
        assert_eq!(
            b64_decode(&b"DfK01KFnj2hsqkCYANqV".to_vec()).unwrap(),
            b"\r\xf2\xb4\xd4\xa1g\x8fhl\xaa@\x98\x00\xda\x95".to_vec()
        );
        assert_eq!(
            b64_decode(&b"GvpWGsJlwK3vfAfPqbdP".to_vec()).unwrap(),
            b"\x1a\xfaV\x1a\xc2e\xc0\xad\xef|\x07\xcf\xa9\xb7O".to_vec()
        );
        assert_eq!(
            b64_decode(&b"wjB7X4Gs".to_vec()).unwrap(),
            b"\xc20{_\x81\xac".to_vec()
        );
        assert_eq!(
            b64_decode(&b"Qqg1rOkOdi2LVLN83g==".to_vec()).unwrap(),
            b"B\xa85\xac\xe9\x0ev-\x8bT\xb3|\xde".to_vec()
        );
        assert_eq!(
            b64_decode(&b"BeDuU3P9WTkLN4T8Lew=".to_vec()).unwrap(),
            b"\x05\xe0\xeeSs\xfdY9\x0b7\x84\xfc-\xec".to_vec()
        );
        assert_eq!(
            b64_decode(&b"UWqS+j+l419b3oKXeySy+dWYDHkV5FKN".to_vec()).unwrap(),
            b"Qj\x92\xfa?\xa5\xe3_[\xde\x82\x97{$\xb2\xf9\xd5\x98\x0cy\x15\xe4R\x8d".to_vec()
        );
        assert_eq!(
            b64_decode(&b"hTPgwB3B".to_vec()).unwrap(),
            b"\x853\xe0\xc0\x1d\xc1".to_vec()
        );
        assert_eq!(
            b64_decode(&b"fTLQE22NjyOc9SzH".to_vec()).unwrap(),
            b"}2\xd0\x13m\x8d\x8f#\x9c\xf5,\xc7".to_vec()
        );
    }

    #[test]
    fn b64_mime_encode_test()
    {
        
        assert_eq!(
            b64_mime_encode(&b"\xf0y\t\x14\xd161n\x03e\xed\x0e\x05\xdf\xc1\xb9\xda".to_vec()),
            b"8HkJFNE2MW4DZe0OBd/Budo=".to_vec()
        );
        assert_eq!(
            b64_mime_encode(&b"*.\x8e\x1d@\x1ac\xdd;\x9a\xcc \x0c\xc2KI".to_vec()),
            b"Ki6OHUAaY907mswgDMJLSQ==".to_vec()
        );
        assert_eq!(b64_mime_encode(&b"\xd6\x829\x82\xbc\x00\xc9\xfe\x03".to_vec()), b"1oI5grwAyf4D".to_vec());
        assert_eq!(
            b64_mime_encode(&b"\r\xf2\xb4\xd4\xa1g\x8fhl\xaa@\x98\x00\xda\x95".to_vec()),
            b"DfK01KFnj2hsqkCYANqV".to_vec()
        );
        assert_eq!(
            b64_mime_encode(&b"\x1a\xfaV\x1a\xc2e\xc0\xad\xef|\x07\xcf\xa9\xb7O".to_vec()),
            b"GvpWGsJlwK3vfAfPqbdP".to_vec())
    }

    #[test]
    fn b64_mime_decode_test()
    {
        assert_eq!(
            b64_mime_decode(&b"1oI5grwAyf4D".to_vec()).unwrap(),
            b"\xd6\x829\x82\xbc\x00\xc9\xfe\x03".to_vec()
        );
        assert_eq!(
            b64_mime_decode(&b"DfK01KFnj2hsqkCYANqV".to_vec()).unwrap(),
            b"\r\xf2\xb4\xd4\xa1g\x8fhl\xaa@\x98\x00\xda\x95".to_vec()
        );
        assert_eq!(
            b64_mime_decode(&b"GvpWGsJlwK3vfAfPqbdP".to_vec()).unwrap(),
            b"\x1a\xfaV\x1a\xc2e\xc0\xad\xef|\x07\xcf\xa9\xb7O".to_vec()
        );
        assert_eq!(
            b64_mime_decode(&b"wjB7X4Gs".to_vec()).unwrap(),
            b"\xc20{_\x81\xac".to_vec()
        );
        assert_eq!(
            b64_mime_decode(&b"Qqg1rOkOdi2LVLN83g==".to_vec()).unwrap(),
            b"B\xa85\xac\xe9\x0ev-\x8bT\xb3|\xde".to_vec()
        );
        assert_eq!(
            b64_mime_decode(&b"BeDuU3P9WTkLN4T8Lew=".to_vec()).unwrap(),
            b"\x05\xe0\xeeSs\xfdY9\x0b7\x84\xfc-\xec".to_vec()
        );
        assert_eq!(
            b64_mime_decode(&b"UWqS+j+l419b3oKXeySy+dWYDHkV5FKN".to_vec()).unwrap(),
            b"Qj\x92\xfa?\xa5\xe3_[\xde\x82\x97{$\xb2\xf9\xd5\x98\x0cy\x15\xe4R\x8d".to_vec()
        );
    }
}
