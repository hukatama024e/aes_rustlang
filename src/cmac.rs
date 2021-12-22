use std::convert::TryInto;
use hex;

#[cfg(test)]
use crate::{aes128, aes192, aes256};

const BLOCK_SIZE : usize = 16;
const SUBKEY_GEN_R128 : [u8; BLOCK_SIZE] = [0x00, 0x00, 0x00, 0x00, 
                                            0x00, 0x00, 0x00, 0x00, 
                                            0x00, 0x00, 0x00, 0x00, 
                                            0x00, 0x00, 0x00, 0x87];

pub fn generate_aes_cmac( plain_text : String,  key : String, cipher_func : fn( String, String ) -> String ) -> String {
    let subkey = generate_subkey( key.clone(), cipher_func );
    let mut blocks = text_to_blocks( plain_text.clone() );
    let block_length = blocks.len();
    let mut result = "00000000000000000000000000000000".to_string();

    // judge text is complte block
    if plain_text.len() != 0 && plain_text.len() % BLOCK_SIZE == 0 {
        blocks[block_length- 1] = xor_block( subkey.0, blocks[block_length - 1] );
    }
    else {
        blocks[block_length- 1] = xor_block( subkey.1, blocks[block_length - 1] ) ; 
    }

    for i in 0..block_length {
        result = cipher_func( hex::encode( xor_block( string_to_block( result ), blocks[i] ) ), key.clone() );
    }

    result
}

fn generate_subkey( key : String, cipher_func : fn( String, String ) -> String ) -> ( [u8; BLOCK_SIZE], [u8; BLOCK_SIZE] ) {
    let k1 : [u8; BLOCK_SIZE];
    let k2 : [u8; BLOCK_SIZE];

    let l : [u8; BLOCK_SIZE] = string_to_block( cipher_func( "00000000000000000000000000000000".to_string(), key ) );
                
    if l[0] & 0x80 == 0x00 {
        k1 = left_shift_block_1bit( l );
    }
    else {
        k1 = xor_block( left_shift_block_1bit( l ), SUBKEY_GEN_R128 );
    }

    if k1[0] & 0x80 == 0x00 {
        k2 = left_shift_block_1bit( k1 );
    }
    else {
        k2 = xor_block( left_shift_block_1bit( k1 ), SUBKEY_GEN_R128 );
    }

    ( k1, k2 )
}

fn string_to_block( input : String ) -> [u8; BLOCK_SIZE] {
  hex::decode( input ).expect( "Failed to convert key in string_to_block" )
                      .try_into()
                      .expect( "Failed to convert key in string_to_block" )
}

fn left_shift_block_1bit( input : [u8; BLOCK_SIZE] ) -> [u8; BLOCK_SIZE] {
    let mut output: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];

    for i in 0..BLOCK_SIZE {
        if ( i != 0 ) && ( input[i] & 0x80 != 0x00 ) {
            output[i - 1] += 0x01;
        }

        output[i] = input[i] << 1;
    }
    
    output
}

fn xor_block( input1 : [u8; BLOCK_SIZE], input2 : [u8; BLOCK_SIZE] ) -> [u8; BLOCK_SIZE] {
    let mut output: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];

    for i in 0..BLOCK_SIZE {
        output[i] = input1[i] ^ input2[i];
    }
    
    output
}

fn text_to_blocks( text : String ) -> Vec<[u8; BLOCK_SIZE]> {
    let block_num : usize;

    if text.len() == 0 {
        block_num = 1;
    }
    else {
        block_num = ( ( ( text.len() as f32 ) / 2.0 ) / BLOCK_SIZE as f32 ).ceil() as usize;
    }

    let mut blocks : Vec<[u8; BLOCK_SIZE]> = Vec::with_capacity( block_num );
    let hex_data = hex::decode( add_padding( text, block_num * BLOCK_SIZE ) ).expect( "Failed to convert in text_to_blocks" );

    for block_index in 0..block_num {
        let mut temp_block : [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
        
        for block_pos in 0..BLOCK_SIZE {
            temp_block[ block_pos ] = hex_data[ block_index * BLOCK_SIZE + block_pos ];
        }

        blocks.push( temp_block ); 
    }

    blocks
}

fn add_padding( input_text : String, byte_num : usize ) -> String {
    let output_text : String;
    let text_length = input_text.len();

    if text_length == byte_num * 2 {
        output_text = input_text;
    }
    else {
        output_text = input_text + &"80" + &"00".repeat( byte_num - text_length / 2 - 1 ).to_string();
    }

    output_text
}

#[test]
fn test_generate_subkey()
{
    //NIST Special Publication 800-38B Appendix D: Examples
    //http://csrc.nist.gov/groups/ST/toolkit/examples.html
    let key = ["2b7e151628aed2a6abf7158809cf4f3c",
               "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
               "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"];

    let cipher_func = [ aes128::encrypt,
                        aes192::encrypt,
                        aes256::encrypt];

    let expect_k1 = ["fbeed618357133667c85e08f7236a8de",
                     "448a5b1c93514b273ee6439dd4daa296",
                     "cad1ed03299eedac2e9a99808621502f"];

    let expect_k2 = ["f7ddac306ae266ccf90bc11ee46d513b",
                     "8914b63926a2964e7dcc873ba9b5452c",
                     "95a3da06533ddb585d3533010c42a0d9"];
    
    for i in 0..key.len() {
        let actual_result = generate_subkey( key[i].to_string(), cipher_func[i] );

        assert_eq!( hex::encode( actual_result.0 ), expect_k1[i] );
        assert_eq!( hex::encode( actual_result.1 ), expect_k2[i] );
    }
}