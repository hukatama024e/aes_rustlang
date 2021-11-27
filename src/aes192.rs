use hex;
use crate::aes_common;

const ROUND_NUM : usize = 12;
const KEY_LENGTH : usize = 6;

const R_CON : [u8; 8] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80];

pub fn encrypt( text : String, key : String ) -> String
{
    let round_key = key_expansion( key );
    let result = cipher( text, round_key );

    result
}

pub fn decrypt( text : String, key : String ) -> String
{
    let round_key = key_expansion( key );
    let result = inv_cipher( text, round_key );

    result
}

fn cipher( plain_text : String, round_key : [u32; aes_common::BLOCK_SIZE * ( ROUND_NUM + 1 )] ) -> String {
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

fn inv_cipher( plain_text : String, round_key : [u32; aes_common::BLOCK_SIZE * ( ROUND_NUM + 1 )] ) -> String {
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

fn key_expansion( key : String ) ->  [u32; aes_common::BLOCK_SIZE*( ROUND_NUM + 1 )] {
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

    //FIPS 197 p38 C.2 AES-192 (Nk=6, Nr=12)
    let input_data = ["00112233445566778899aabbccddeeff",
                      "5f72641557f5bc92f7be3b291db9f91a",
                      "9f487f794f955f662afc86abd7f1ab29",
                      "b7a53ecbbf9d75a0c40efc79b674cc11",
                      "7a1e98bdacb6d1141a6944dd06eb2d3e",
                      "aaa755b34cffe57cef6f98e1f01c13e6",
                      "921f748fd96e937d622d7725ba8ba50c",
                      "e913e7b18f507d4b227ef652758acbcc",
                      "6cf5edf996eb0a069c4ef21cbfc25762",
                      "7478bcdce8a50b81d4327a9009188262",
                      "0d73cc2d8f6abe8b0cf2dd9bb83d422e",
                      "71d720933b6d677dc00b8f28238e0fb7",
                      "793e76979c3403e9aab7b2d10fa96ccc"];

    let expect = ["00102030405060708090a0b0c0d0e0f0",
                  "4f63760643e0aa85aff8c9d041fa0de4",
                  "cb02818c17d2af9c62aa64428bb25fd7",
                  "f75c7778a327c8ed8cfebfc1a6c37f53",
                  "22ffc916a81474416496f19c64ae2532",
                  "80121e0776fd1d8a8d8c31bc965d1fee",
                  "671ef1fd4e2a1e03dfdcb1ef3d789b30",
                  "0c0370d00c01e622166b8accd6db3a2c",
                  "7255dad30fb80310e00d6c6b40d0527c",
                  "a906b254968af4e9b4bdb2d2f0c44336",
                  "88ec930ef5e7e4b6cc32f4c906d29414",
                  "afb73eeb1cd1b85162280f27fb20d585",
                  "dda97ca4864cdfe06eaf70a0ec0d7191"];

    let round_key_str = ["000102030405060708090a0b0c0d0e0f",
                         "10111213141516175846f2f95c43f4fe",
                         "544afef55847f0fa4856e2e95c43f4fe",
                         "40f949b31cbabd4d48f043b810b7b342",
                         "58e151ab04a2a5557effb5416245080c",
                         "2ab54bb43a02f8f662e3a95d66410c08",
                         "f501857297448d7ebdf1c6ca87f33e3c",
                         "e510976183519b6934157c9ea351f1e0",
                         "1ea0372a995309167c439e77ff12051e",
                         "dd7e0e887e2fff68608fc842f9dcc154",
                         "859f5f237a8d5a3dc0c02952beefd63a",
                         "de601e7827bcdf2ca223800fd8aeda32",
                         "a4970a331a78dc09c418c271e3a41d5d"];

    let round = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
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

    //FIPS 197 p28 A.2 Expansion of a 192-bit Cipher Key
    let key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
    
    let expect : [u32; 52] = [0x8e73_b0f7, 0xda0e_6452, 0xc810_f32b, 0x8090_79e5, 0x62f8_ead2, 0x522c_6b7b,
                              0xfe0c_91f7, 0x2402_f5a5, 0xec12_068e, 0x6c82_7f6b, 0x0e7a_95b9, 0x5c56_fec2,
                              0x4db7_b4bd, 0x69b5_4118, 0x85a7_4796, 0xe925_38fd, 0xe75f_ad44, 0xbb09_5386,
                              0x485a_f057, 0x21ef_b14f, 0xa448_f6d9, 0x4d6d_ce24, 0xaa32_6360, 0x113b_30e6,
                              0xa25e_7ed5, 0x83b1_cf9a, 0x27f9_3943, 0x6a94_f767, 0xc0a6_9407, 0xd19d_a4e1,
                              0xec17_86eb, 0x6fa6_4971, 0x485f_7032, 0x22cb_8755, 0xe26d_1352, 0x33f0_b7b3,
                              0x40be_eb28, 0x2f18_a259, 0x6747_d26b, 0x458c_553e, 0xa7e1_466c, 0x9411_f1df,
                              0x821f_750a, 0xad07_d753, 0xca40_0538, 0x8fcc_5006, 0x282d_166a, 0xbc3c_e7b5,
                              0xe98b_a06f, 0x448c_773c, 0x8ecc_7204, 0x0100_2202];

    let actual_result = key_expansion( key.to_string() );

    for i in 0..expect.len() {
        assert_eq!( actual_result[i], expect[i] );
    }
}