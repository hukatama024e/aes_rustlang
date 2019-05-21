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

#[test]
fn test_cli_aes128_ecb_encrypt() {
    
    //SP 800-38A p24 F.1.1 ECB-AES128.Encrypt(+PKCS#7 padding)
    let text = "6bc1bee22e409f96e93d7e117393172a\
                ae2d8a571e03ac9c9eb76fac45af8e51\
                30c81c46a35ce411e5fbc1191a0a52ef\
                f69f2445df4f9b17ad2b417be66c3710";

    let key = "2b7e151628aed2a6abf7158809cf4f3c";

    let expect = "3ad77bb40d7a3660a89ecaf32466ef97\
                  f5d3d58503b9699de785895a96fdbaaf\
                  43b1cd7f598ece23881b00e3ed030688\
                  7b0c785e27e8ad3f8223207104725dd4\
                  a254be88e037ddd9d79fb6411c3f9df8\n";

    let mut cmd = Command::cargo_bin( env!( "CARGO_PKG_NAME" ) ).expect( "Failed to get binary" );

    cmd.arg( text )
        .arg( key )
        .arg( "-k" )
        .arg( "aes128" )
        .arg( "-o" )
        .arg( "ecb-encrypt" )
        .assert()
        .success()
        .stdout( expect );
}

#[test]
fn test_cli_aes192_ecb_encrypt() {
    
    //SP 800-38A p25 F.1.3 ECB-AES192.Encrypt(+PKCS#7 padding)
    let text = "6bc1bee22e409f96e93d7e117393172a\
                ae2d8a571e03ac9c9eb76fac45af8e51\
                30c81c46a35ce411e5fbc1191a0a52ef\
                f69f2445df4f9b17ad2b417be66c3710";

    let key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";

    let expect = "bd334f1d6e45f25ff712a214571fa5cc\
                  974104846d0ad3ad7734ecb3ecee4eef\
                  ef7afd2270e2e60adce0ba2face6444e\
                  9a4b41ba738d6c72fb16691603c18e0e\
                  daa0af074bd8083c8a32d4fc563c55cc\n";

    let mut cmd = Command::cargo_bin( env!( "CARGO_PKG_NAME" ) ).expect( "Failed to get binary" );

    cmd.arg( text )
        .arg( key )
        .arg( "-k" )
        .arg( "aes192" )
        .arg( "-o" )
        .arg( "ecb-encrypt" )
        .assert()
        .success()
        .stdout( expect );
}

#[test]
fn test_cli_aes256_ecb_encrypt() {
    
    //SP 800-38A p26 F.1.5 ECB-AES256.Encrypt(+PKCS#7 padding)
    let text = "6bc1bee22e409f96e93d7e117393172a\
                ae2d8a571e03ac9c9eb76fac45af8e51\
                30c81c46a35ce411e5fbc1191a0a52ef\
                f69f2445df4f9b17ad2b417be66c3710";

    let key = "603deb1015ca71be2b73aef0857d7781\
               1f352c073b6108d72d9810a30914dff4";

    let expect = "f3eed1bdb5d2a03c064b5a7e3db181f8\
                  591ccb10d410ed26dc5ba74a31362870\
                  b6ed21b99ca6f4f9f153e7b1beafed1d\
                  23304b7a39f9f3ff067d8d8f9e24ecc7\
                  4c45dfb3b3b484ec35b0512dc8c1c4d6\n";

    let mut cmd = Command::cargo_bin( env!( "CARGO_PKG_NAME" ) ).expect( "Failed to get binary" );

    cmd.arg( text )
        .arg( key )
        .arg( "-k" )
        .arg( "aes256" )
        .arg( "-o" )
        .arg( "ecb-encrypt" )
        .assert()
        .success()
        .stdout( expect );
}

#[test]
fn test_cli_aes128_cbc_encrypt() {
    
    //SP 800-38A p27 F.2.1 CBC-AES128.Encrypt(+PKCS#7 padding)
    let text = "6bc1bee22e409f96e93d7e117393172a\
                ae2d8a571e03ac9c9eb76fac45af8e51\
                30c81c46a35ce411e5fbc1191a0a52ef\
                f69f2445df4f9b17ad2b417be66c3710";

    let key = "2b7e151628aed2a6abf7158809cf4f3c";

    let iv = "000102030405060708090a0b0c0d0e0f";

    let expect = "7649abac8119b246cee98e9b12e9197d\
                  5086cb9b507219ee95db113a917678b2\
                  73bed6b8e3c1743b7116e69e22229516\
                  3ff1caa1681fac09120eca307586e1a7\
                  8cb82807230e1321d3fae00d18cc2012\n";

    let mut cmd = Command::cargo_bin( env!( "CARGO_PKG_NAME" ) ).expect( "Failed to get binary" );

    cmd.arg( text )
        .arg( key )
        .arg( "-i" )
        .arg( iv )
        .arg( "-k" )
        .arg( "aes128" )
        .arg( "-o" )
        .arg( "cbc-encrypt" )
        .assert()
        .success()
        .stdout( expect );
}

#[test]
fn test_cli_aes192_cbc_encrypt() {
    
    //SP 800-38A p28 F.2.3 CBC-AES192.Encrypt(+PKCS#7 padding)
    let text = "6bc1bee22e409f96e93d7e117393172a\
                ae2d8a571e03ac9c9eb76fac45af8e51\
                30c81c46a35ce411e5fbc1191a0a52ef\
                f69f2445df4f9b17ad2b417be66c3710";

    let key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";

    let iv = "000102030405060708090a0b0c0d0e0f";

    let expect = "4f021db243bc633d7178183a9fa071e8\
                  b4d9ada9ad7dedf4e5e738763f69145a\
                  571b242012fb7ae07fa9baac3df102e0\
                  08b0e27988598881d920a9e64f5615cd\
                  612ccd79224b350935d45dd6a98f8176\n";

    let mut cmd = Command::cargo_bin( env!( "CARGO_PKG_NAME" ) ).expect( "Failed to get binary" );

    cmd.arg( text )
        .arg( key )
        .arg( "-i" )
        .arg( iv )
        .arg( "-k" )
        .arg( "aes192" )
        .arg( "-o" )
        .arg( "cbc-encrypt" )
        .assert()
        .success()
        .stdout( expect );
}

#[test]
fn test_cli_aes256_cbc_encrypt() {
    
    //SP 800-38A p28 F.2.5 CBC-AES256.Encrypt(+PKCS#7 padding)
    let text = "6bc1bee22e409f96e93d7e117393172a\
                ae2d8a571e03ac9c9eb76fac45af8e51\
                30c81c46a35ce411e5fbc1191a0a52ef\
                f69f2445df4f9b17ad2b417be66c3710";

    let key = "603deb1015ca71be2b73aef0857d7781\
               1f352c073b6108d72d9810a30914dff4";

    let iv = "000102030405060708090a0b0c0d0e0f";

    let expect = "f58c4c04d6e5f1ba779eabfb5f7bfbd6\
                  9cfc4e967edb808d679f777bc6702c7d\
                  39f23369a9d9bacfa530e26304231461\
                  b2eb05e2c39be9fcda6c19078c6a9d1b\
                  3f461796d6b0d6b2e0c2a72b4d80e644\n";

    let mut cmd = Command::cargo_bin( env!( "CARGO_PKG_NAME" ) ).expect( "Failed to get binary" );

    cmd.arg( text )
        .arg( key )
        .arg( "-i" )
        .arg( iv )
        .arg( "-k" )
        .arg( "aes256" )
        .arg( "-o" )
        .arg( "cbc-encrypt" )
        .assert()
        .success()
        .stdout( expect );
}

#[test]
fn test_cli_aes128_ecb_decrypt() {
    
    //SP 800-38A p24 F.1.2 ECB-AES128.Decrypt(+PKCS#7 padding)
    let text = "3ad77bb40d7a3660a89ecaf32466ef97\
                f5d3d58503b9699de785895a96fdbaaf\
                43b1cd7f598ece23881b00e3ed030688\
                7b0c785e27e8ad3f8223207104725dd4\
                a254be88e037ddd9d79fb6411c3f9df8";

    let key = "2b7e151628aed2a6abf7158809cf4f3c";

    let expect = "6bc1bee22e409f96e93d7e117393172a\
                  ae2d8a571e03ac9c9eb76fac45af8e51\
                  30c81c46a35ce411e5fbc1191a0a52ef\
                  f69f2445df4f9b17ad2b417be66c3710\n";

    let mut cmd = Command::cargo_bin( env!( "CARGO_PKG_NAME" ) ).expect( "Failed to get binary" );

    cmd.arg( text )
        .arg( key )
        .arg( "-k" )
        .arg( "aes128" )
        .arg( "-o" )
        .arg( "ecb-decrypt" )
        .assert()
        .success()
        .stdout( expect );
}

#[test]
fn test_cli_aes192_ecb_decrypt() {
    
    //SP 800-38A p25 F.1.4 ECB-AES192.Decrypt(+PKCS#7 padding)
    let text = "bd334f1d6e45f25ff712a214571fa5cc\
                  974104846d0ad3ad7734ecb3ecee4eef\
                  ef7afd2270e2e60adce0ba2face6444e\
                  9a4b41ba738d6c72fb16691603c18e0e\
                  daa0af074bd8083c8a32d4fc563c55cc";



    let key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";

    let expect = "6bc1bee22e409f96e93d7e117393172a\
                  ae2d8a571e03ac9c9eb76fac45af8e51\
                  30c81c46a35ce411e5fbc1191a0a52ef\
                  f69f2445df4f9b17ad2b417be66c3710\n";

    let mut cmd = Command::cargo_bin( env!( "CARGO_PKG_NAME" ) ).expect( "Failed to get binary" );

    cmd.arg( text )
        .arg( key )
        .arg( "-k" )
        .arg( "aes192" )
        .arg( "-o" )
        .arg( "ecb-decrypt" )
        .assert()
        .success()
        .stdout( expect );
}

#[test]
fn test_cli_aes256_ecb_decrypt() {
    
    //SP 800-38A p26 F.1.6 ECB-AES256.Decrypt(+PKCS#7 padding)
    let text = "f3eed1bdb5d2a03c064b5a7e3db181f8\
                591ccb10d410ed26dc5ba74a31362870\
                b6ed21b99ca6f4f9f153e7b1beafed1d\
                23304b7a39f9f3ff067d8d8f9e24ecc7\
                4c45dfb3b3b484ec35b0512dc8c1c4d6";

    let key = "603deb1015ca71be2b73aef0857d7781\
               1f352c073b6108d72d9810a30914dff4";

    let expect = "6bc1bee22e409f96e93d7e117393172a\
                  ae2d8a571e03ac9c9eb76fac45af8e51\
                  30c81c46a35ce411e5fbc1191a0a52ef\
                  f69f2445df4f9b17ad2b417be66c3710\n";

    let mut cmd = Command::cargo_bin( env!( "CARGO_PKG_NAME" ) ).expect( "Failed to get binary" );

    cmd.arg( text )
        .arg( key )
        .arg( "-k" )
        .arg( "aes256" )
        .arg( "-o" )
        .arg( "ecb-decrypt" )
        .assert()
        .success()
        .stdout( expect );
}