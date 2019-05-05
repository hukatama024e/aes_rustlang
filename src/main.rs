#[macro_use]
extern crate clap;

use clap::{App, AppSettings, Arg, ArgMatches, ErrorKind};
use aes_rustlang::{aes128, aes192, aes256, block_cipher_mode};

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
                .possible_values(&["encrypt", "decrypt", "ecb-encrypt", "ecb-decrypt"])
                .default_value( "encrypt" )
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

    let result = match &*format!( "{}-{}", key_length, operate_mode ) {
        "aes128-encrypt" => encrypt_aes128( text.to_string(), key.to_string() ),
        "aes192-encrypt" => encrypt_aes192( text.to_string(), key.to_string() ),
        "aes256-encrypt" => encrypt_aes256( text.to_string(), key.to_string() ),
        "aes128-ecb-encrypt" => block_cipher_mode::encrypt_ecb_mode(text.to_string(), key.to_string(), encrypt_aes128 ),
        "aes192-ecb-encrypt" => block_cipher_mode::encrypt_ecb_mode(text.to_string(), key.to_string(), encrypt_aes192 ),
        "aes256-ecb-encrypt" => block_cipher_mode::encrypt_ecb_mode(text.to_string(), key.to_string(), encrypt_aes256 ),
        "aes128-decrypt" => decrypt_aes128( text.to_string(), key.to_string() ),
        "aes192-decrypt" => decrypt_aes192( text.to_string(), key.to_string() ),
        "aes256-decrypt" => decrypt_aes256( text.to_string(), key.to_string() ),
        _ => unreachable!()
    };

    result
}

fn encrypt_aes128( text : String, key : String ) -> String
{
    let round_key = aes128::key_expansion( key );
    let result = aes128::cipher( text, round_key );

    result
}

fn encrypt_aes192( text : String, key : String ) -> String
{
    let round_key = aes192::key_expansion( key );
    let result = aes192::cipher( text, round_key );

    result
}

fn encrypt_aes256( text : String, key : String ) -> String
{
    let round_key = aes256::key_expansion( key );
    let result = aes256::cipher( text, round_key );

    result
}

fn decrypt_aes128( text : String, key : String ) -> String
{
    let round_key = aes128::key_expansion( key );
    let result = aes128::inv_cipher( text, round_key );

    result
}

fn decrypt_aes192( text : String, key : String ) -> String
{
    let round_key = aes192::key_expansion( key );
    let result = aes192::inv_cipher( text, round_key );

    result
}

fn decrypt_aes256( text : String, key : String ) -> String
{
    let round_key = aes256::key_expansion( key );
    let result = aes256::inv_cipher( text, round_key );

    result
}