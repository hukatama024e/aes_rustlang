use hex;
use crate::aes_common;

const ROUND_NUM : usize = 14;
const KEY_LENGTH : usize = 8;

const R_CON : [u8; 7] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];

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
        else if i % KEY_LENGTH == 4 {
            temp = aes_common::sub_word( temp );
        }

        round_key[i] = round_key[i - KEY_LENGTH] ^ temp;
        i += 1;
    }

    return round_key;
}

#[test]
fn test_add_round_key() {

    //FIPS 197 p42 C.3 AES-256 (Nk=8, Nr=14)
    let input_data = ["00112233445566778899aabbccddeeff",
                      "5f72641557f5bc92f7be3b291db9f91a",
                      "bd2a395d2b6ac438d192443e615da195",
                      "810dce0cc9db8172b3678c1e88a1b5bd",
                      "b2822d81abe6fb275faf103a078c0033",
                      "aeb65ba974e0f822d73f567bdb64c877",
                      "b951c33c02e9bd29ae25cdb1efa08cc7",
                      "ebb19e1c3ee7c9e87d7535e9ed6b9144",
                      "5174c8669da98435a8b3e62ca974a5ea",
                      "0f77ee31d2ccadc05430a83f4ef96ac3",
                      "bd86f0ea748fc4f4630f11c1e9331233",
                      "af8690415d6e1dd387e5fbedd5c89013",
                      "7427fae4d8a695269ce83d315be0392b",
                      "2c21a820306f154ab712c75eee0da04f",
                      "aa5ece06ee6e3c56dde68bac2621bebf"];

    let expect = ["00102030405060708090a0b0c0d0e0f0",
                  "4f63760643e0aa85efa7213201a4e705",
                  "1859fbc28a1c00a078ed8aadc42f6109",
                  "975c66c1cb9f3fa8a93a28df8ee10f63",
                  "1c05f271a417e04ff921c5c104701554",
                  "c357aae11b45b7b0a2c7bd28a8dc99fa",
                  "7f074143cb4e243ec10c815d8375d54c",
                  "d653a4696ca0bc0f5acaab5db96c5e7d",
                  "5aa858395fd28d7d05e1a38868f3b9c5",
                  "4a824851c57e7e47643de50c2af3e8c9",
                  "c14907f6ca3b3aa070e9aa313b52b5ec",
                  "5f9c6abfbac634aa50409fa766677653",
                  "516604954353950314fb86e401922521",
                  "627bceb9999d5aaac945ecf423f56da5",
                  "8ea2b7ca516745bfeafc49904b496089"];

    let round_key_str = ["000102030405060708090a0b0c0d0e0f",
                         "101112131415161718191a1b1c1d1e1f",
                         "a573c29fa176c498a97fce93a572c09c",
                         "1651a8cd0244beda1a5da4c10640bade",
                         "ae87dff00ff11b68a68ed5fb03fc1567",
                         "6de1f1486fa54f9275f8eb5373b8518d",
                         "c656827fc9a799176f294cec6cd5598b",
                         "3de23a75524775e727bf9eb45407cf39",
                         "0bdc905fc27b0948ad5245a4c1871c2f",
                         "45f5a66017b2d387300d4d33640a820a",
                         "7ccff71cbeb4fe5413e6bbf0d261a7df",
                         "f01afafee7a82979d7a5644ab3afe640",
                         "2541fe719bf500258813bbd55a721c0a",
                         "4e5a6699a9f24fe07e572baacdf8cdea",
                         "24fc79ccbf0979e9371ac23c6d68de36"];

    let round = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
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

    //FIPS 197 p30 A.3 Expansion of a 256-bit Cipher Key
    let key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
    
    let expect : [u32; 60] = [0x603d_eb10, 0x15ca_71be, 0x2b73_aef0, 0x857d_7781, 0x1f35_2c07, 0x3b61_08d7,
                              0x2d98_10a3, 0x0914_dff4, 0x9ba3_5411, 0x8e69_25af, 0xa51a_8b5f, 0x2067_fcde,
                              0xa8b0_9c1a, 0x93d1_94cd, 0xbe49_846e, 0xb75d_5b9a, 0xd59a_ecb8, 0x5bf3_c917,
                              0xfee9_4248, 0xde8e_be96, 0xb5a9_328a, 0x2678_a647, 0x9831_2229, 0x2f6c_79b3,
                              0x812c_81ad, 0xdadf_48ba, 0x2436_0af2, 0xfab8_b464, 0x98c5_bfc9, 0xbebd_198e,
                              0x268c_3ba7, 0x09e0_4214, 0x6800_7bac, 0xb2df_3316, 0x96e9_39e4, 0x6c51_8d80,
                              0xc814_e204, 0x76a9_fb8a, 0x5025_c02d, 0x59c5_8239, 0xde13_6967, 0x6ccc_5a71,
                              0xfa25_6395, 0x9674_ee15, 0x5886_ca5d, 0x2e2f_31d7, 0x7e0a_f1fa, 0x27cf_73c3,
                              0x749c_47ab, 0x1850_1dda, 0xe275_7e4f, 0x7401_905a, 0xcafa_aae3, 0xe4d5_9b34,
                              0x9adf_6ace, 0xbd10_190d, 0xfe48_90d1, 0xe618_8d0b, 0x046d_f344, 0x706c_631e];

    let actual_result = key_expansion( key.to_string() );

    for i in 0..expect.len() {
        assert_eq!( actual_result[i], expect[i] );
    }
}