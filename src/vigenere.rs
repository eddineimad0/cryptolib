//#########################################################################o
// The Vigenere cipher is a method of encrypting alphabetic text           |
// by using a series of interwoven Caesar ciphers, based on the            |
// letters of a keyword. It employs a form of polyalphabetic substitution. |
// The primary weakness of the Vigenère cipher is the repeating nature of  |
// its key. If a cryptanalyst correctly guesses the key's length n,        |
// deciphering it becomes as easy as deciphering a serie Caesar shifts.    |
//#########################################################################o

////////////////////////////////////////////////////////////////////////////
/// Preform vigener encryption on a string using a given key.
/// # Arguments
/// * `msg`: the string to be encrypted.
/// * `key`: the key to be used in the encryption.
/// # Returns
/// the Vigenere encryption of the string.
/// # Note
/// '''
/// Due to the cipher using only latin-alphabet characters,
/// the key parameter is filtered so that it only contains
/// ascii alphabetic characters.
/// any non ascii alphabetic character in the message is left as is.
/// '''
/////////////////////////////////////////////////////////////////////////////
pub fn vigenere_enc(msg:&str,key:&str)->String 
{
    if key.len() == 0 || msg.len() == 0
    {
        return msg.to_owned();
    }
    let key:String = key.chars().filter(|&ch| ch.is_ascii_alphabetic()).collect();
    let mut key_final_len = (msg.len() + key.len() - 1)/key.len();
    let mut ext_key = String::from(&key);
    while key_final_len > 1
    {
        ext_key.push_str(&key);
        key_final_len -= 1;
    }
    ext_key.make_ascii_uppercase();
    let mut key_index = 0;
    msg.chars().map(|ch|{
        if ch.is_ascii_alphabetic()
        {
           let base = if ch.is_ascii_lowercase(){b'a'}else{b'A'};
           let res = (base + (ch as u8 - base +  (ext_key.as_bytes()[key_index] - b'A')) % 26) as char;
           key_index += 1;
           res
        }
        else 
        {
            ch
        }
    }).collect()
}

/////////////////////////////////////////////////////////////////////////
/// Decrypt a vigener encrypted string.
/// # Arguments
/// * `msg`: the string to be decrypted.
/// * `key`: the key used in the encryption.
/// # Returns
/// the plaintext string.
/// # Note
/// '''
/// Due to the cipher using only latin-alphabet characters,
/// the key parameter is filtered so that it only contains
/// ascii alphabetic characters.
/// any non ascii alphabetic character in the message is left as is.
/// '''
/////////////////////////////////////////////////////////////////////////
pub fn vigenere_dec(msg:&str,key:&str)->String 
{
    if key.len() == 0 || msg.len() == 0
    {
        return msg.to_owned();
    }
    let key:String = key.chars().filter(|&ch| ch.is_ascii_alphabetic()).collect();
    let mut key_final_len = (msg.len() + key.len() - 1)/key.len();
    let mut ext_key = String::from(&key);
    while key_final_len > 1
    {
        ext_key.push_str(&key);
        key_final_len -= 1;
    }
    ext_key.make_ascii_uppercase();
    let mut key_index = 0;
    msg.chars().map(|ch|{
        if ch.is_ascii_alphabetic()
        {
           let base = if ch.is_ascii_lowercase(){b'a'}else{b'A'};
           let res = (base + (ch as u8 - base + (26 + b'A' - ext_key.as_bytes()[key_index])) % 26) as char;
           key_index += 1;
           res
        }
        else 
        {
            ch
        }
    }).collect()
}

#[cfg(test)]
mod tests{
    use super::*;   

    #[test]
    fn empty() {
        assert_eq!(vigenere_enc("", "test"), "");
    }

    #[test]
    fn vigenere_simple() {
        assert_eq!(
            vigenere_enc("THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG", "LION"),
            "EPSDFQQXMZCJYNCKUCACDWJRCBVRWINLOWU"
        );

        assert_eq!(
            vigenere_enc("cryptoisshortforcryptography", "abcd"),
            "csastpkvsiqutgqucsastpiuaqjb"
        );

    }

    #[test]
    fn vigenere_with_spaces() {
        assert_eq!(
            vigenere_enc(
                "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
                "spaces"
            ),
            "Ddrgq ahhuo hgddr uml sbev, ggfheexwljr chahxsemfy tlkx."
        );
    }

    #[test]
    fn vigenere_unicode_and_numbers() {
        assert_eq!(
            vigenere_enc("1 Lorem ⏳ ipsum dolor sit amet Ѡ", "unicode"),
            "1 Fbzga ⏳ ltmhu fcosl fqv opin Ѡ"
        );
    }

    #[test]
    fn vigenere_unicode_key() {
        assert_eq!(
            vigenere_enc("Lorem ipsum dolor sit amet", "😉 key!"),
            "Vspoq gzwsw hmvsp cmr kqcd"
        );
    }

    #[test]
    fn vigenere_empty_key() {
        assert_eq!(vigenere_enc("Lorem ipsum", ""), "Lorem ipsum");
    }

    #[test]
    fn vigenere_dec_test(){
        assert_eq!(vigenere_dec("IHSQIRIHCQCU", "IOZQGH"),"ATTACKATDAWN");
    }
}
