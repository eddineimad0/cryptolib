//#######################################################################o
// The action of a Caesar cipher is to replace each plaintext            |
// letter with a different one a fixed number of places down             |
// the alphabet.                                                         |
// As with all single-alphabet substitution ciphers,                     |
// the Caesar cipher is easily broken and in modern practice             |
// offers essentially no communications security.                        |
//#######################################################################o

////////////////////////////////////////////////////////////
/// `ShiftDirection` represent the direction in which 
/// caesar cipher rotate the characters.
/// # Values
/// Left
/// Right
////////////////////////////////////////////////////////////
pub enum ShiftDirection
{
    Left,
    Right,
}
////////////////////////////////////////////////////////////////////////////
/// Apply the caesar cipher to a given string.
///# Arguments
///*`data`: refrence to the string to be encrypted.
///*`shift`: value by which the characters are shifted.
///*`direction`: the shift direction.
///# Returns
/// A String that contains the cipher's output.
///# Note
/// '''
/// Due to the of the cipher only using latin-alphabet characters,
/// the shift is only applied to ascii alphabet characters any other utf-8
/// character is left as is.
/// '''
///////////////////////////////////////////////////////////////////////////
pub fn caesar_enc(data:&str,shift:u8,direction:ShiftDirection)->String
{    
    if shift == 0 
    {
        return String::from(data);
    }
    let mut offset = shift % 26;
    offset = match direction{
        ShiftDirection::Left => 26 - (offset % 26), // calculate the corresponding Right Shift.
        ShiftDirection::Right => offset,
    };
    data.chars().map(|ch|{
        if ch.is_ascii_alphabetic()
        {
            let base = if ch.is_ascii_lowercase(){b'a'}else{b'A'};
            ( base + ((ch as u8 - base) + offset) % 26) as char
        }
        else 
        {
            ch
        }
    }).collect()
}


////////////////////////////////////////////////////////////////////////////
/// Decrypt a caesar encrypted string.
///# Arguments
///*`data`: refrence to the string to be decrypted.
///*`shift`: value by which the characters were shifted.
///*`direction`: the shift direction.
///# Returns
/// A String that contains the plaintext output.
///# Note
/// '''
/// Due to the of the cipher only using latin-alphabet characters,
/// the shift is only applied to ascii alphabet characters any other utf-8
/// character is left as is.
/// '''
///////////////////////////////////////////////////////////////////////////
pub fn caesar_dec(data:&str,shift:u8,direction:ShiftDirection)->String
{
    if shift == 0 
    {
        return String::from(data);
    }
    let mut offset = shift % 26;
    offset = match direction{
        ShiftDirection::Left => offset,
        ShiftDirection::Right => 26 - offset,// calculate the corresponding Left Shift.
    };

    data.chars().map(|ch|{
        if ch.is_ascii_alphabetic()
        {
            let base = if ch.is_ascii_lowercase(){b'a'}else{b'A'};
            ( base + ((ch as u8 - base) + offset) % 26) as char
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
   pub fn test_enc()
   {
       assert_eq!(caesar_enc("THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG",23,ShiftDirection::Right),"QEB NRFZH YOLTK CLU GRJMP LSBO QEB IXWV ALD".to_owned());

       assert_eq!(caesar_enc("ABCDEFGHIJKLMNOPQRSTUVWXYZ",1,ShiftDirection::Left),"ZABCDEFGHIJKLMNOPQRSTUVWXY".to_owned());

       assert_eq!(caesar_enc("attack at dawn 攻",5,ShiftDirection::Right),"fyyfhp fy ifbs 攻".to_owned());
       assert_eq!(caesar_enc("ABCDEFGHIJKLMNOPQRSTUVWXYZ",0,ShiftDirection::Left),"ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_owned());
   }

   #[test]
   pub fn test_dec()
   {
       assert_eq!(caesar_dec("QEB NRFZH YOLTK CLU GRJMP LSBO QEB IXWV ALD",23,ShiftDirection::Right),"THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG".to_owned());
       assert_eq!(caesar_dec("QEB NRFZH YOLTK CLU GRJMP LSBO QEB IXWV ALD",3,ShiftDirection::Left),"THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG".to_owned());
       assert_eq!(caesar_dec("Pm ol ohk hufaopun jvumpkluaphs av zhf, ol dyval pa pu jpwoly, aoha pz, if zv johunpun aol vykly vm aol slaalyz vm aol hswohila, aoha uva h dvyk jvbsk il thkl vba.",7,ShiftDirection::Right),"If he had anything confidential to say, he wrote it in cipher, that is, by so changing the order of the letters of the alphabet, that not a word could be made out.");
   }

}
