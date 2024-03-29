#[macro_use]
extern crate clap;

use clap::{App, AppSettings, Arg, ArgMatches, ErrorKind};
use aes_rustlang::{aes128, aes192, aes256, block_cipher_mode, cmac};

fn main() {
    let args = get_args();

    match args {
        Ok( args ) => println!( "{}", execute_aes( args ) ),
        Err( e ) => {
            if e.kind == ErrorKind::HelpDisplayed || e.kind == ErrorKind::VersionDisplayed {
                println!( "{}", e.message )
            }
            else {
                eprintln!( "{}", e.message )
            }
        },
    }
}

fn get_args<'a>() -> clap::Result<ArgMatches<'a>> {
    App::new( crate_name!() )
        .version( crate_version!() )
        .about( crate_description!() )
        .setting( AppSettings::UnifiedHelpMessage )
        .arg(
            Arg::with_name( "TEXT" )
                .help( "Plain text for encryption or encrypted text for decryption" )
                .required( true )
                .index( 1 )
        )
        .arg(
            Arg::with_name( "KEYS" )
                .help( "Keys for encryption or decryption" )
                .required( true )
                .index( 2 )
        )
        .arg(
            Arg::with_name( "KEY_LENGTH" )
                .short( "kl" )
                .long( "key_length" )
                .help( "Key length parameter")
                .possible_values( &["aes128", "aes192", "aes256"] )
                .default_value( "aes128" )
                .takes_value( true )
        )
        .arg(
            Arg::with_name( "OPERATE_MODE" )
                .short( "opmode" )
                .long( "operate_mode" )
                .help( "Operation mode")
                .possible_values( &["encrypt", "decrypt", "ecb-encrypt", "ecb-decrypt", "cbc-encrypt", "cbc-decrypt", "cmac"] )
                .default_value( "encrypt" )
                .takes_value( true )
        )
        .arg(
            Arg::with_name( "INITIALIZATION_VECTOR" )
                .short( "iv" )
                .long( "initilzation_vector" )
                .help( "Initilzation vector")
                .default_value( "" )
                .takes_value( true )
        )
        .get_matches_safe()
}

fn execute_aes( args : ArgMatches ) -> String
{
    let text = args.value_of( "TEXT" ).unwrap_or_default();
    let key = args.value_of( "KEYS" ).unwrap_or_default();
    let key_length = args.value_of( "KEY_LENGTH" ).unwrap_or_default();
    let operate_mode = args.value_of( "OPERATE_MODE" ).unwrap_or_default();
    let iv = args.value_of( "INITIALIZATION_VECTOR" ).unwrap_or_default();

    let result = match &*format!( "{}-{}", key_length, operate_mode ) {
        "aes128-encrypt" => aes128::encrypt( text.to_string(), key.to_string() ),
        "aes192-encrypt" => aes192::encrypt( text.to_string(), key.to_string() ),
        "aes256-encrypt" => aes256::encrypt( text.to_string(), key.to_string() ),
        "aes128-ecb-encrypt" => block_cipher_mode::encrypt_ecb_mode(text.to_string(), key.to_string(), aes128::encrypt ),
        "aes192-ecb-encrypt" => block_cipher_mode::encrypt_ecb_mode(text.to_string(), key.to_string(), aes192::encrypt ),
        "aes256-ecb-encrypt" => block_cipher_mode::encrypt_ecb_mode(text.to_string(), key.to_string(), aes256::encrypt ),
        "aes128-cbc-encrypt" => block_cipher_mode::encrypt_cbc_mode(text.to_string(), key.to_string(), iv.to_string(), aes128::encrypt ),
        "aes192-cbc-encrypt" => block_cipher_mode::encrypt_cbc_mode(text.to_string(), key.to_string(), iv.to_string(), aes192::encrypt ),
        "aes256-cbc-encrypt" => block_cipher_mode::encrypt_cbc_mode(text.to_string(), key.to_string(), iv.to_string(), aes256::encrypt ),
        "aes128-decrypt" => aes128::decrypt( text.to_string(), key.to_string() ),
        "aes192-decrypt" => aes192::decrypt( text.to_string(), key.to_string() ),
        "aes256-decrypt" => aes256::decrypt( text.to_string(), key.to_string() ),
        "aes128-ecb-decrypt" => block_cipher_mode::decrypt_ecb_mode(text.to_string(), key.to_string(), aes128::decrypt ),
        "aes192-ecb-decrypt" => block_cipher_mode::decrypt_ecb_mode(text.to_string(), key.to_string(), aes192::decrypt ),
        "aes256-ecb-decrypt" => block_cipher_mode::decrypt_ecb_mode(text.to_string(), key.to_string(), aes256::decrypt ),
        "aes128-cbc-decrypt" => block_cipher_mode::decrypt_cbc_mode(text.to_string(), key.to_string(), iv.to_string(), aes128::decrypt ),
        "aes192-cbc-decrypt" => block_cipher_mode::decrypt_cbc_mode(text.to_string(), key.to_string(), iv.to_string(), aes192::decrypt ),
        "aes256-cbc-decrypt" => block_cipher_mode::decrypt_cbc_mode(text.to_string(), key.to_string(), iv.to_string(), aes256::decrypt ),
        "aes128-cmac" => cmac::generate_aes_cmac(text.to_string(), key.to_string(), aes128::encrypt ),
        "aes192-cmac" => cmac::generate_aes_cmac(text.to_string(), key.to_string(), aes192::encrypt ),
        "aes256-cmac" => cmac::generate_aes_cmac(text.to_string(), key.to_string(), aes256::encrypt ),
        _ => unreachable!()
    };

    result
}