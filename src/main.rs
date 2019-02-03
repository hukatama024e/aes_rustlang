use aes_rustlang::aes128;

fn main() {

    //FIPS 197 p35 C.1 AES-128 (Nk=4, Nr=10)
    let key = [ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                0x06, 0x07, 0x08, 0x09, 0x0a, 
                0x0b, 0x0c, 0x0d, 0x0e, 0x0f ];

    let round_key = aes128::key_expansion( key );
    let result = aes128::cipher( "00112233445566778899aabbccddeeff".to_string(), round_key );

    println!( "{}", result );
}