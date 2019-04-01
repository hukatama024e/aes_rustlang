use std::process::Command;
use assert_cmd::prelude::*;

#[test]
fn test_cli_aes128_encrypt() {
    
    //FIPS 197 p35 C.1 AES-128 (Nk=4, Nr=10)
    let text = "00112233445566778899aabbccddeeff";
    let key = "000102030405060708090a0b0c0d0e0f";
    let expect = "69c4e0d86a7b0430d8cdb78070b4c55a\n";

    let mut cmd = Command::cargo_bin( env!( "CARGO_PKG_NAME" ) ).expect( "Failed to get binary" );

    cmd.arg( text )
        .arg( key )
        .arg( "-k" )
        .arg( "aes128" )
        .arg( "-o" )
        .arg( "encrypt" )
        .assert()
        .success()
        .stdout( expect );
}

#[test]
fn test_cli_aes128_decrypt() {
    
    //FIPS 197 p35 C.1 AES-128 (Nk=4, Nr=10)
    let text = "69c4e0d86a7b0430d8cdb78070b4c55a";
    let key = "000102030405060708090a0b0c0d0e0f";
    let expect = "00112233445566778899aabbccddeeff\n";

    let mut cmd = Command::cargo_bin( env!( "CARGO_PKG_NAME" ) ).expect( "Failed to get binary" );

    cmd.arg( text )
        .arg( key )
        .arg( "-k" )
        .arg( "aes128" )
        .arg( "-o" )
        .arg( "decrypt" )
        .assert()
        .success()
        .stdout( expect );
}