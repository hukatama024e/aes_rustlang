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

fn add_padding( text : String ) -> String {
    let mut padding_num = ( text.len() % CIPHER_BLOCK_SIZE ) / 2;
    if padding_num == 0 {
        padding_num = CIPHER_BLOCK_SIZE / 2; 
    }

    let padding_text = format!( "{:0x}", padding_num );
    let padded_text = format!( "{}{}", text, padding_text.repeat( padding_num ) );

    padded_text
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