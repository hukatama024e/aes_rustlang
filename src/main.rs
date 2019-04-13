#[macro_use]
extern crate clap;

use clap::{App, AppSettings, Arg, ArgMatches, ErrorKind};
use aes_rustlang::{aes128, aes192, aes256};

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
                .possible_values(&["encrypt", "decrypt"])
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
    let opmode = args.value_of( "OPERATE_MODE" ).unwrap_or_default();

    let result = match key_length {
        "aes128" => execute_aes128( text, key, opmode ),
        "aes192" => execute_aes192( text, key, opmode ),
        "aes256" => execute_aes256( text, key, opmode ),
        _ => unreachable!()
    };

    result
}

fn execute_aes128( text : &str, key : &str, operate_mode : &str ) -> String
{
    let round_key = aes128::key_expansion( key.to_string() );

    let result = match &*format!( "{}", operate_mode ) {
        "encrypt" => aes128::cipher( text.to_string(), round_key ),
        "decrypt" => aes128::inv_cipher( text.to_string(), round_key ),
        _ => unreachable!()
    };

    result
}

fn execute_aes192( text : &str, key : &str, operate_mode : &str ) -> String
{
    let round_key = aes192::key_expansion( key.to_string() );

    let result = match &*format!( "{}", operate_mode ) {
        "encrypt" => aes192::cipher( text.to_string(), round_key ),
        "decrypt" => aes192::inv_cipher( text.to_string(), round_key ),
        _ => unreachable!()
    };

    result
}

fn execute_aes256( text : &str, key : &str, operate_mode : &str ) -> String
{
    let round_key = aes256::key_expansion( key.to_string() );

    let result = match &*format!( "{}", operate_mode ) {
        "encrypt" => aes256::cipher( text.to_string(), round_key ),
        "decrypt" => aes256::inv_cipher( text.to_string(), round_key ),
        _ => unreachable!()
    };

    result
}