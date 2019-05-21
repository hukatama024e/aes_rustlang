use hex;
use std::cmp;

const CIPHER_BLOCK_SIZE : usize = 32;

pub fn encrypt_ecb_mode( plain_text : String, key : String, cipher_func : fn( String, String ) -> String ) -> String {
    let text = add_padding( plain_text );
    let input_blocks = divide_blocks( text );
    let mut output_blocks : Vec<String> = Vec::new();

    for i in 0..input_blocks.len() {
        output_blocks.push( cipher_func( input_blocks[ i ].clone(), key.clone() ) );
    }

    output_blocks.join( "" )
}

pub fn encrypt_cbc_mode( plain_text : String, key : String, iv : String, cipher_func : fn( String, String ) -> String ) -> String {
    let text = add_padding( plain_text );
    let input_blocks = divide_blocks( text );
    let mut output_blocks : Vec<String> = Vec::new();
    let mut next_xor_text = iv;

    for i in 0..input_blocks.len() {
        let input_text = xor_text( input_blocks[i].clone(), next_xor_text );
        output_blocks.push( cipher_func( input_text, key.clone() ) );
        next_xor_text = output_blocks[ i ].clone();
    }

    output_blocks.join( "" )
}

pub fn decrypt_ecb_mode( cipher_text : String, key : String, inv_cipher_func : fn( String, String ) -> String ) -> String {
    let input_blocks = divide_blocks( cipher_text );
    let mut output_blocks : Vec<String> = Vec::new();

    for i in 0..input_blocks.len() {
        output_blocks.push( inv_cipher_func( input_blocks[ i ].clone(), key.clone() ) );
    }

    remove_padding( output_blocks.join( "" ) )
}

fn add_padding( text : String ) -> String {
    let padding_num = ( CIPHER_BLOCK_SIZE - ( text.len() % CIPHER_BLOCK_SIZE ) ) / 2;
    let padding_text = format!( "{:02x}", padding_num );
    let padded_text = format!( "{}{}", text, padding_text.repeat( padding_num ) );

    padded_text
}

fn remove_padding( text : String ) -> String {
    let padding_last_str = text.chars().rev().take( 2 ).collect::<String>().chars().rev().collect::<String>();
    let padding_num = hex::decode( padding_last_str ).expect( "Failed to convert padding num" )[0];

    let text_len = text.len();
    let mut removed_text = text;

    for i in 0..( padding_num * 2 ) {
        removed_text.remove( text_len - ( i as usize ) - 1 );
    }

    removed_text
}

fn divide_blocks( text : String ) -> Vec<String> {
    let mut blocks : Vec<String> = Vec::new();
    let mut temp_str = text;

    while !temp_str.is_empty() {
        let ( block, rest_str ) = temp_str.split_at( cmp::min( CIPHER_BLOCK_SIZE, temp_str.len() ) );
        blocks.push( block.to_string() );
        temp_str = rest_str.to_string();
    }

    blocks
}

fn xor_text( text1 : String, text2 : String ) -> String {
    assert!( text1.len() == text2.len() );

    let text1_hex = hex::decode( text1 ).expect( "Failed to convert text to hex" );
    let text2_hex = hex::decode( text2 ).expect( "Failed to convert text to hex" );
    let mut xor_hex = Vec::new();

    for i in 0..text1_hex.len() {
        xor_hex.push( text1_hex[i] ^ text2_hex[i] );
    }

    hex::encode( xor_hex )
}

#[test]
fn test_add_padding() {
    let input = ["XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
                 "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
                 "XXXXXXXXXXXXXXXXXXXXXXXXXXXX",
                 "XXXXXXXXXXXXXXXXXXXXXXXXXX",
                 "XXXXXXXXXXXXXXXXXXXXXXXX",
                 "XXXXXXXXXXXXXXXXXXXXXX",
                 "XXXXXXXXXXXXXXXXXXXX",
                 "XXXXXXXXXXXXXXXXXX",
                 "XXXXXXXXXXXXXXXX",
                 "XXXXXXXXXXXXXX",
                 "XXXXXXXXXXXX",
                 "XXXXXXXXXX",
                 "XXXXXXXX",
                 "XXXXXX",
                 "XXXX",
                 "XX",
    ];

    let expect = ["XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX10101010101010101010101010101010",
                 "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX01",
                 "XXXXXXXXXXXXXXXXXXXXXXXXXXXX0202",
                 "XXXXXXXXXXXXXXXXXXXXXXXXXX030303",
                 "XXXXXXXXXXXXXXXXXXXXXXXX04040404",
                 "XXXXXXXXXXXXXXXXXXXXXX0505050505",
                 "XXXXXXXXXXXXXXXXXXXX060606060606",
                 "XXXXXXXXXXXXXXXXXX07070707070707",
                 "XXXXXXXXXXXXXXXX0808080808080808",
                 "XXXXXXXXXXXXXX090909090909090909",
                 "XXXXXXXXXXXX0a0a0a0a0a0a0a0a0a0a",
                 "XXXXXXXXXX0b0b0b0b0b0b0b0b0b0b0b",
                 "XXXXXXXX0c0c0c0c0c0c0c0c0c0c0c0c",
                 "XXXXXX0d0d0d0d0d0d0d0d0d0d0d0d0d",
                 "XXXX0e0e0e0e0e0e0e0e0e0e0e0e0e0e",
                 "XX0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f",
    ];

    for i in 0..input.len() {
        let actual = add_padding( input[i].to_string() );
        assert_eq!( actual, expect[i].to_string() );
    }
}

#[test]
fn test_remove_padding() {
    let input = ["XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX10101010101010101010101010101010",
                 "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX01",
                 "XXXXXXXXXXXXXXXXXXXXXXXXXXXX0202",
                 "XXXXXXXXXXXXXXXXXXXXXXXXXX030303",
                 "XXXXXXXXXXXXXXXXXXXXXXXX04040404",
                 "XXXXXXXXXXXXXXXXXXXXXX0505050505",
                 "XXXXXXXXXXXXXXXXXXXX060606060606",
                 "XXXXXXXXXXXXXXXXXX07070707070707",
                 "XXXXXXXXXXXXXXXX0808080808080808",
                 "XXXXXXXXXXXXXX090909090909090909",
                 "XXXXXXXXXXXX0a0a0a0a0a0a0a0a0a0a",
                 "XXXXXXXXXX0b0b0b0b0b0b0b0b0b0b0b",
                 "XXXXXXXX0c0c0c0c0c0c0c0c0c0c0c0c",
                 "XXXXXX0d0d0d0d0d0d0d0d0d0d0d0d0d",
                 "XXXX0e0e0e0e0e0e0e0e0e0e0e0e0e0e",
                 "XX0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f",
    ];

    let expect = ["XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
                  "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
                  "XXXXXXXXXXXXXXXXXXXXXXXXXXXX",
                  "XXXXXXXXXXXXXXXXXXXXXXXXXX",
                  "XXXXXXXXXXXXXXXXXXXXXXXX",
                  "XXXXXXXXXXXXXXXXXXXXXX",
                  "XXXXXXXXXXXXXXXXXXXX",
                  "XXXXXXXXXXXXXXXXXX",
                  "XXXXXXXXXXXXXXXX",
                  "XXXXXXXXXXXXXX",
                  "XXXXXXXXXXXX",
                  "XXXXXXXXXX",
                  "XXXXXXXX",
                  "XXXXXX",
                  "XXXX",
                  "XX",
    ];

    for i in 0..input.len() {
        let actual = remove_padding( input[i].to_string() );
        assert_eq!( actual, expect[i].to_string() );
    }
}