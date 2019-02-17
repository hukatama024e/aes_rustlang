use aes_rustlang::aes128;


#[test]
fn test_cipher() {

    //FIPS 197 p35 C.1 AES-128 (Nk=4, Nr=10)
    let round_key : [u32; 44] = [ 0x2b7e_1516, 0x28ae_d2a6, 0xabf7_1588, 0x09cf_4f3c, 0xa0fa_fe17, 0x8854_2cb1, 
                                  0x23a3_3939, 0x2a6c_7605, 0xf2c2_95f2, 0x7a96_b943, 0x5935_807a, 0x7359_f67f,
                                  0x3d80_477d, 0x4716_fe3e, 0x1e23_7e44, 0x6d7a_883b, 0xef44_a541, 0xa852_5b7f,
                                  0xb671_253b, 0xdb0b_ad00, 0xd4d1_c6f8, 0x7c83_9d87, 0xcaf2_b8bc, 0x11f9_15bc,
                                  0x6d88_a37a, 0x110b_3efd, 0xdbf9_8641, 0xca00_93fd, 0x4e54_f70e, 0x5f5f_c9f3,
                                  0x84a6_4fb2, 0x4ea6_dc4f, 0xead2_7321, 0xb58d_bad2, 0x312b_f560, 0x7f8d_292f,
                                  0xac77_66f3, 0x19fa_dc21, 0x28d1_2941, 0x575c_006e, 0xd014_f9a8, 0xc9ee_2589,
                                  0xe13f_0cc8, 0xb663_0ca6 ];

    let expect = "69c4e0d86a7b0430d8cdb78070b4c55a";

    let actual_result = aes128::cipher( "00112233445566778899aabbccddeeff".to_string(), round_key );

    assert_eq!( actual_result, expect );
}


#[test]
fn test_key_expansion() {

    //FIPS 197 p27 A.1 Expansion of a 128-bit Cipher Key
    let key = [ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2,
                0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c ];
    
    let expect : [u32; 44] = [ 0x2b7e_1516, 0x28ae_d2a6, 0xabf7_1588, 0x09cf_4f3c, 0xa0fa_fe17, 0x8854_2cb1, 
                               0x23a3_3939, 0x2a6c_7605, 0xf2c2_95f2, 0x7a96_b943, 0x5935_807a, 0x7359_f67f,
                               0x3d80_477d, 0x4716_fe3e, 0x1e23_7e44, 0x6d7a_883b, 0xef44_a541, 0xa852_5b7f,
                               0xb671_253b, 0xdb0b_ad00, 0xd4d1_c6f8, 0x7c83_9d87, 0xcaf2_b8bc, 0x11f9_15bc,
                               0x6d88_a37a, 0x110b_3efd, 0xdbf9_8641, 0xca00_93fd, 0x4e54_f70e, 0x5f5f_c9f3,
                               0x84a6_4fb2, 0x4ea6_dc4f, 0xead2_7321, 0xb58d_bad2, 0x312b_f560, 0x7f8d_292f,
                               0xac77_66f3, 0x19fa_dc21, 0x28d1_2941, 0x575c_006e, 0xd014_f9a8, 0xc9ee_2589,
                               0xe13f_0cc8, 0xb663_0ca6 ];

    let actual_result = aes128::key_expansion( key );

    for i in 0..expect.len() {
        assert_eq!( actual_result[i], expect[i] );
    }
}
