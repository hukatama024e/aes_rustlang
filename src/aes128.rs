use hex;
use crate::aes_common;

const ROUND_NUM : usize = 10;
const KEY_LENGTH : usize = 4;

const R_CON : [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

pub fn cipher( plain_text : String, round_key : [u32; aes_common::BLOCK_SIZE * ( ROUND_NUM + 1 )] ) -> String {
    let mut state : [[u8; aes_common::WORD_IN_BYTES_NUM]; aes_common::BLOCK_SIZE] = aes_common::text_to_state( plain_text );
    let encrypted_text : String;

    state = add_round_key( state, round_key, 0 );

    for round in 1..ROUND_NUM {
        state = aes_common::sub_bytes( state );
        state = aes_common::shift_rows( state );
        state = aes_common::mix_columns( state );
        state = add_round_key( state, round_key, round );
    }

    state = aes_common::sub_bytes( state );
    state = aes_common::shift_rows( state );
    state = add_round_key( state, round_key, ROUND_NUM );

    encrypted_text = aes_common::state_to_text( state );

    return encrypted_text;
}

pub fn inv_cipher( plain_text : String, round_key : [u32; aes_common::BLOCK_SIZE * ( ROUND_NUM + 1 )] ) -> String {
    let mut state : [[u8; aes_common::WORD_IN_BYTES_NUM]; aes_common::BLOCK_SIZE] = aes_common::text_to_state( plain_text );
    let decrypted_text : String;

    state = add_round_key( state, round_key, ROUND_NUM );

    for round in ( 1..ROUND_NUM ).rev() {
        state = aes_common::inv_shift_rows( state );
        state = aes_common::inv_sub_bytes( state );
        state = add_round_key( state, round_key, round );
        state = aes_common::inv_mix_columns( state );
    }

    state = aes_common::inv_shift_rows( state );
    state = aes_common::inv_sub_bytes( state );
    state = add_round_key( state, round_key, 0 );

    decrypted_text = aes_common::state_to_text( state );

    return decrypted_text;
}

fn add_round_key( input_state : [[u8; aes_common::WORD_IN_BYTES_NUM]; aes_common::BLOCK_SIZE],
                    round_key : [u32; aes_common::BLOCK_SIZE * ( ROUND_NUM + 1 )], round : usize ) -> [[u8; aes_common::WORD_IN_BYTES_NUM]; aes_common::BLOCK_SIZE] {
    let mut output_state : [[u8; aes_common::WORD_IN_BYTES_NUM]; aes_common::BLOCK_SIZE] = [[0; aes_common::WORD_IN_BYTES_NUM]; aes_common::BLOCK_SIZE];

    for col in 0..aes_common::WORD_IN_BYTES_NUM {
        output_state[0][col] = input_state[0][col] ^ ( ( round_key[round * aes_common::BLOCK_SIZE + col] >> 24 & 0x000000FF ) as u8 );
        output_state[1][col] = input_state[1][col] ^ ( ( round_key[round * aes_common::BLOCK_SIZE + col] >> 16 & 0x000000FF ) as u8 );
        output_state[2][col] = input_state[2][col] ^ ( ( round_key[round * aes_common::BLOCK_SIZE + col] >> 8 & 0x000000FF ) as u8 );
        output_state[3][col] = input_state[3][col] ^ ( ( round_key[round * aes_common::BLOCK_SIZE + col] & 0x000000FF ) as u8 );
    }

    return output_state;
}

pub fn key_expansion( key : String ) ->  [u32; aes_common::BLOCK_SIZE*( ROUND_NUM + 1 )] {
    let mut round_key : [u32; aes_common::BLOCK_SIZE * ( ROUND_NUM + 1 )] = [0; aes_common::BLOCK_SIZE * ( ROUND_NUM + 1 )];
    let mut i : usize = 0;
    let mut temp : u32;

    let key_u8 = hex::decode( key ).expect( "Failed to convert key in key_expansion" );

    while i < KEY_LENGTH {
        round_key[i] = ( key_u8[i * 4] as u32 ) << 24 |
                        ( key_u8[i * 4 + 1] as u32 ) << 16 | 
                        ( key_u8[i * 4 + 2] as u32 ) << 8 |
                        ( key_u8[i * 4 + 3] as u32 );
        i += 1;
    }

    i = KEY_LENGTH;

    while i < aes_common::BLOCK_SIZE * ( ROUND_NUM + 1 ) {
        temp = round_key[i - 1];

        if i % KEY_LENGTH == 0 {
            temp = aes_common::sub_word( aes_common::rot_word( temp ) ) ^ ( ( R_CON[i / KEY_LENGTH - 1] as u32 ) << 24 );
        }

        round_key[i] = round_key[i - KEY_LENGTH] ^ temp;
        i += 1;
    }

    return round_key;
}

#[test]
fn test_add_round_key() {

    //FIPS 197 p35 C.1 AES-128 (Nk=4, Nr=10)
    let input_data = ["00112233445566778899aabbccddeeff",
                      "5f72641557f5bc92f7be3b291db9f91a",
                      "ff87968431d86a51645151fa773ad009",
                      "4c9c1e66f771f0762c3f868e534df256",
                      "6385b79ffc538df997be478e7547d691",
                      "f4bcd45432e554d075f1d6c51dd03b3c",
                      "9816ee7400f87f556b2c049c8e5ad036",
                      "c57e1c159a9bd286f05f4be098c63439",
                      "baa03de7a1f9b56ed5512cba5f414d23",
                      "e9f74eec023020f61bf2ccf2353c21c7",
                      "7ad5fda789ef4e272bca100b3d9ff59f"];

    let expect = ["00102030405060708090a0b0c0d0e0f0",
                  "89d810e8855ace682d1843d8cb128fe4",
                  "4915598f55e5d7a0daca94fa1f0a63f7",
                  "fa636a2825b339c940668a3157244d17",
                  "247240236966b3fa6ed2753288425b6c",
                  "c81677bc9b7ac93b25027992b0261996",
                  "c62fe109f75eedc3cc79395d84f9cf5d",
                  "d1876c0f79c4300ab45594add66ff41f",
                  "fde3bad205e5d0d73547964ef1fe37f1",
                  "bd6e7c3df2b5779e0b61216e8b10b689",
                  "69c4e0d86a7b0430d8cdb78070b4c55a"];

    let round_key_str = ["000102030405060708090a0b0c0d0e0f",
                         "d6aa74fdd2af72fadaa678f1d6ab76fe",
                         "b692cf0b643dbdf1be9bc5006830b3fe",
                         "b6ff744ed2c2c9bf6c590cbf0469bf41",
                         "47f7f7bc95353e03f96c32bcfd058dfd",
                         "3caaa3e8a99f9deb50f3af57adf622aa",
                         "5e390f7df7a69296a7553dc10aa31f6b",
                         "14f9701ae35fe28c440adf4d4ea9c026",
                         "47438735a41c65b9e016baf4aebf7ad2",
                         "549932d1f08557681093ed9cbe2c974e",
                         "13111d7fe3944a17f307a78b4d2b30c5"];

    let round = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let mut round_key_u32 : [u32; aes_common::BLOCK_SIZE * ( ROUND_NUM + 1 )] = [0; aes_common::BLOCK_SIZE * ( ROUND_NUM + 1 )];

    //round key(string) => round key(u32 array)
    for i in 0..round_key_str.len() {
        let rnd_key_u8 = hex::decode( round_key_str[i] ).expect( "Failed decoding text to u8" );

        for j in 0..4 {  
            round_key_u32[i * aes_common::WORD_IN_BYTES_NUM + j] = ( rnd_key_u8[j * aes_common::WORD_IN_BYTES_NUM] as u32 ) << 24 |
                                                                    ( rnd_key_u8[j * aes_common::WORD_IN_BYTES_NUM + 1] as u32 ) << 16 | 
                                                                    ( rnd_key_u8[j * aes_common::WORD_IN_BYTES_NUM + 2] as u32 ) << 8 |
                                                                    ( rnd_key_u8[j * aes_common::WORD_IN_BYTES_NUM + 3] as u32 );
        }
    }

    for i in 0..expect.len() {
        let actual_result = aes_common::state_to_text( 
            add_round_key( aes_common::text_to_state( input_data[i].to_string() ), round_key_u32, round[i] ) );

        assert_eq!( actual_result, expect[i] );
    }    
}

#[test]
fn test_key_expansion() {

    //FIPS 197 p27 A.1 Expansion of a 128-bit Cipher Key
    let key = "2b7e151628aed2a6abf7158809cf4f3c";
    
    let expect : [u32; 44] = [0x2b7e_1516, 0x28ae_d2a6, 0xabf7_1588, 0x09cf_4f3c, 0xa0fa_fe17, 0x8854_2cb1, 
                              0x23a3_3939, 0x2a6c_7605, 0xf2c2_95f2, 0x7a96_b943, 0x5935_807a, 0x7359_f67f,
                              0x3d80_477d, 0x4716_fe3e, 0x1e23_7e44, 0x6d7a_883b, 0xef44_a541, 0xa852_5b7f,
                              0xb671_253b, 0xdb0b_ad00, 0xd4d1_c6f8, 0x7c83_9d87, 0xcaf2_b8bc, 0x11f9_15bc,
                              0x6d88_a37a, 0x110b_3efd, 0xdbf9_8641, 0xca00_93fd, 0x4e54_f70e, 0x5f5f_c9f3,
                              0x84a6_4fb2, 0x4ea6_dc4f, 0xead2_7321, 0xb58d_bad2, 0x312b_f560, 0x7f8d_292f,
                              0xac77_66f3, 0x19fa_dc21, 0x28d1_2941, 0x575c_006e, 0xd014_f9a8, 0xc9ee_2589,
                              0xe13f_0cc8, 0xb663_0ca6];

    let actual_result = key_expansion( key.to_string() );

    for i in 0..expect.len() {
        assert_eq!( actual_result[i], expect[i] );
    }
}