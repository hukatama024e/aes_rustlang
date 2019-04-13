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

#[test]
fn test_cli_aes192_encrypt() {
    
    //FIPS 197 p38 C.2 AES-192 (Nk=6, Nr=12)
    let text = "00112233445566778899aabbccddeeff";
    let key = "000102030405060708090a0b0c0d0e0f1011121314151617";
    let expect = "dda97ca4864cdfe06eaf70a0ec0d7191\n";

    let mut cmd = Command::cargo_bin( env!( "CARGO_PKG_NAME" ) ).expect( "Failed to get binary" );

    cmd.arg( text )
        .arg( key )
        .arg( "-k" )
        .arg( "aes192" )
        .arg( "-o" )
        .arg( "encrypt" )
        .assert()
        .success()
        .stdout( expect );
}

#[test]
fn test_cli_aes192_decrypt() {
    
    //FIPS 197 p38 C.2 AES-192 (Nk=6, Nr=12)
    let text = "dda97ca4864cdfe06eaf70a0ec0d7191";
    let key = "000102030405060708090a0b0c0d0e0f1011121314151617";
    let expect = "00112233445566778899aabbccddeeff\n";

    let mut cmd = Command::cargo_bin( env!( "CARGO_PKG_NAME" ) ).expect( "Failed to get binary" );

    cmd.arg( text )
        .arg( key )
        .arg( "-k" )
        .arg( "aes192" )
        .arg( "-o" )
        .arg( "decrypt" )
        .assert()
        .success()
        .stdout( expect );
}

#[test]
fn test_cli_aes256_encrypt() {
    
    //FIPS 197 p42 C.3 AES-256 (Nk=8, Nr=14)
    let text = "00112233445566778899aabbccddeeff";
    let key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let expect = "8ea2b7ca516745bfeafc49904b496089\n";

    let mut cmd = Command::cargo_bin( env!( "CARGO_PKG_NAME" ) ).expect( "Failed to get binary" );

    cmd.arg( text )
        .arg( key )
        .arg( "-k" )
        .arg( "aes256" )
        .arg( "-o" )
        .arg( "encrypt" )
        .assert()
        .success()
        .stdout( expect );
}

#[test]
fn test_cli_aes256_decrypt() {
    
    //FIPS 197 p38 C.2 AES-256 (Nk=6, Nr=12)
    let text = "8ea2b7ca516745bfeafc49904b496089";
    let key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let expect = "00112233445566778899aabbccddeeff\n";

    let mut cmd = Command::cargo_bin( env!( "CARGO_PKG_NAME" ) ).expect( "Failed to get binary" );

    cmd.arg( text )
        .arg( key )
        .arg( "-k" )
        .arg( "aes256" )
        .arg( "-o" )
        .arg( "decrypt" )
        .assert()
        .success()
        .stdout( expect );
}