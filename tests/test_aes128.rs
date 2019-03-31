use aes_rustlang::aes128;


#[test]
fn test_cipher() {

    //FIPS 197 p35 C.1 AES-128 (Nk=4, Nr=10)
    let round_key : [u32; 44] = [ 0x0001_0203, 0x0405_0607, 0x0809_0a0b, 0x0c0d_0e0f, 0xd6aa_74fd, 0xd2af_72fa,
                                  0xdaa6_78f1, 0xd6ab_76fe, 0xb692_cf0b, 0x643d_bdf1, 0xbe9b_c500, 0x6830_b3fe,
                                  0xb6ff_744e, 0xd2c2_c9bf, 0x6c59_0cbf, 0x0469_bf41, 0x47f7_f7bc, 0x9535_3e03,
                                  0xf96c_32bc, 0xfd05_8dfd, 0x3caa_a3e8, 0xa99f_9deb, 0x50f3_af57, 0xadf6_22aa,
                                  0x5e39_0f7d, 0xf7a6_9296, 0xa755_3dc1, 0x0aa3_1f6b, 0x14f9_701a, 0xe35f_e28c,
                                  0x440a_df4d, 0x4ea9_c026, 0x4743_8735, 0xa41c_65b9, 0xe016_baf4, 0xaebf_7ad2,
                                  0x5499_32d1, 0xf085_5768, 0x1093_ed9c, 0xbe2c_974e, 0x1311_1d7f, 0xe394_4a17,
                                  0xf307_a78b, 0x4d2b_30c5 ];

    let expect = "69c4e0d86a7b0430d8cdb78070b4c55a";

    let actual_result = aes128::cipher( "00112233445566778899aabbccddeeff".to_string(), round_key );

    assert_eq!( actual_result, expect );
}

#[test]
fn test_inv_cipher() {

    //FIPS 197 p35 C.1 AES-128 (Nk=4, Nr=10)
    let round_key : [u32; 44] = [ 0x0001_0203, 0x0405_0607, 0x0809_0a0b, 0x0c0d_0e0f, 0xd6aa_74fd, 0xd2af_72fa,
                                  0xdaa6_78f1, 0xd6ab_76fe, 0xb692_cf0b, 0x643d_bdf1, 0xbe9b_c500, 0x6830_b3fe,
                                  0xb6ff_744e, 0xd2c2_c9bf, 0x6c59_0cbf, 0x0469_bf41, 0x47f7_f7bc, 0x9535_3e03,
                                  0xf96c_32bc, 0xfd05_8dfd, 0x3caa_a3e8, 0xa99f_9deb, 0x50f3_af57, 0xadf6_22aa,
                                  0x5e39_0f7d, 0xf7a6_9296, 0xa755_3dc1, 0x0aa3_1f6b, 0x14f9_701a, 0xe35f_e28c,
                                  0x440a_df4d, 0x4ea9_c026, 0x4743_8735, 0xa41c_65b9, 0xe016_baf4, 0xaebf_7ad2,
                                  0x5499_32d1, 0xf085_5768, 0x1093_ed9c, 0xbe2c_974e, 0x1311_1d7f, 0xe394_4a17,
                                  0xf307_a78b, 0x4d2b_30c5 ];

    let expect = "00112233445566778899aabbccddeeff";

    let actual_result = aes128::inv_cipher( "69c4e0d86a7b0430d8cdb78070b4c55a".to_string(), round_key );

    assert_eq!( actual_result, expect );
}

#[test]
fn test_key_expansion() {

    //FIPS 197 p27 A.1 Expansion of a 128-bit Cipher Key
    let key = "2b7e151628aed2a6abf7158809cf4f3c";
    
    let expect : [u32; 44] = [ 0x2b7e_1516, 0x28ae_d2a6, 0xabf7_1588, 0x09cf_4f3c, 0xa0fa_fe17, 0x8854_2cb1, 
                               0x23a3_3939, 0x2a6c_7605, 0xf2c2_95f2, 0x7a96_b943, 0x5935_807a, 0x7359_f67f,
                               0x3d80_477d, 0x4716_fe3e, 0x1e23_7e44, 0x6d7a_883b, 0xef44_a541, 0xa852_5b7f,
                               0xb671_253b, 0xdb0b_ad00, 0xd4d1_c6f8, 0x7c83_9d87, 0xcaf2_b8bc, 0x11f9_15bc,
                               0x6d88_a37a, 0x110b_3efd, 0xdbf9_8641, 0xca00_93fd, 0x4e54_f70e, 0x5f5f_c9f3,
                               0x84a6_4fb2, 0x4ea6_dc4f, 0xead2_7321, 0xb58d_bad2, 0x312b_f560, 0x7f8d_292f,
                               0xac77_66f3, 0x19fa_dc21, 0x28d1_2941, 0x575c_006e, 0xd014_f9a8, 0xc9ee_2589,
                               0xe13f_0cc8, 0xb663_0ca6 ];

    let actual_result = aes128::key_expansion( key.to_string() );

    for i in 0..expect.len() {
        assert_eq!( actual_result[i], expect[i] );
    }
}
