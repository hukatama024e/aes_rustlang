use hex;

pub const WORD_IN_BYTES_NUM : usize = 4;
pub const BLOCK_SIZE : usize = 4;

// Irreducible polynomial(0x11B) to 8bit
// When XOR calculation, MSB translate to 0. So 0x11B can translate to 0x1B in 8bit valiable calculation
const IRR_POLYNOMIAL : u8 = 0x1B;

const S_BOX : [[u8; 16]; 16] = [
    [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
    [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
    [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
    [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
    [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
    [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
    [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
    [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
    [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
    [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
    [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
    [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
    [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
    [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
    [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
    [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
];

const INV_S_BOX : [[u8; 16]; 16] = [
    [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb], 
    [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb], 
    [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e], 
    [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25], 
    [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92], 
    [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84], 
    [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06], 
    [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b], 
    [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73], 
    [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e], 
    [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b], 
    [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4], 
    [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f], 
    [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef], 
    [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61], 
    [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]
];

pub fn text_to_state( text : String ) -> [[u8; WORD_IN_BYTES_NUM]; BLOCK_SIZE] {
    let mut state : [[u8; WORD_IN_BYTES_NUM]; BLOCK_SIZE] = [[0; WORD_IN_BYTES_NUM]; BLOCK_SIZE];

    // check text length
    assert!( text.len() == BLOCK_SIZE * WORD_IN_BYTES_NUM * 2 );

    let hex_data = hex::decode( text ).expect( "Failed decoding text to state" );

    for col in 0..WORD_IN_BYTES_NUM {
        for row in 0..BLOCK_SIZE {
            state[row][col] = hex_data[row + WORD_IN_BYTES_NUM * col];
        }
    }

    return state;
}

pub fn state_to_text( state : [[u8; WORD_IN_BYTES_NUM]; BLOCK_SIZE] ) -> String {
    let mut hex_data : Vec<u8> = vec![0; BLOCK_SIZE * WORD_IN_BYTES_NUM];

    for col in 0..WORD_IN_BYTES_NUM {
        for row in 0..BLOCK_SIZE {
            hex_data[row + WORD_IN_BYTES_NUM * col] = state[row][col];
        }
    }

    let text = hex::encode( hex_data );

    return text;
}

pub fn sub_bytes( input_state : [[u8; WORD_IN_BYTES_NUM]; BLOCK_SIZE] ) -> [[u8; WORD_IN_BYTES_NUM]; BLOCK_SIZE] {
    let mut output_state : [[u8; WORD_IN_BYTES_NUM]; BLOCK_SIZE] = [[0; WORD_IN_BYTES_NUM]; BLOCK_SIZE];

    for col in 0..WORD_IN_BYTES_NUM {
        for row in 0..BLOCK_SIZE {
            let x = ( ( input_state[row][col] & 0xF0 ) >> 4 ) as usize;
            let y = ( input_state[row][col] & 0x0F ) as usize;

            output_state[row][col] = S_BOX[x][y];
        }
    }    

    return output_state;
}

pub fn shift_rows( input_state : [[u8; WORD_IN_BYTES_NUM]; BLOCK_SIZE] ) -> [[u8; WORD_IN_BYTES_NUM]; BLOCK_SIZE] {
    let mut output_state : [[u8; WORD_IN_BYTES_NUM]; BLOCK_SIZE] = [[0; WORD_IN_BYTES_NUM]; BLOCK_SIZE];

    for row in 0..BLOCK_SIZE {
        for col in 0..WORD_IN_BYTES_NUM {
            let new_col_pos = ( col + row ) % WORD_IN_BYTES_NUM;
            output_state[row][col] = input_state[row][new_col_pos];
        }
    }

    return output_state;
}

pub fn mix_columns( input_state : [[u8; WORD_IN_BYTES_NUM]; BLOCK_SIZE] ) -> [[u8; WORD_IN_BYTES_NUM]; BLOCK_SIZE] {
    let mut output_state : [[u8; WORD_IN_BYTES_NUM]; BLOCK_SIZE] = [[0; WORD_IN_BYTES_NUM]; BLOCK_SIZE];

    for col in 0..WORD_IN_BYTES_NUM {
        output_state[0][col] = multiplication( input_state[0][col], 2 ) ^ multiplication( input_state[1][col], 3 ) ^
                                input_state[2][col] ^ input_state[3][col];

        output_state[1][col] = input_state[0][col] ^ multiplication( input_state[1][col], 2 ) ^
                                multiplication( input_state[2][col], 3 ) ^ input_state[3][col];

        output_state[2][col] = input_state[0][col] ^ input_state[1][col] ^
                                multiplication( input_state[2][col], 2 ) ^ multiplication( input_state[3][col], 3 );

        output_state[3][col] = multiplication( input_state[0][col], 3 ) ^ input_state[1][col] ^
                                input_state[2][col] ^ multiplication( input_state[3][col], 2 );
    }

    return output_state;
}

pub fn inv_sub_bytes( input_state : [[u8; WORD_IN_BYTES_NUM]; BLOCK_SIZE] ) -> [[u8; WORD_IN_BYTES_NUM]; BLOCK_SIZE] {
    let mut output_state : [[u8; WORD_IN_BYTES_NUM]; BLOCK_SIZE] = [[0; WORD_IN_BYTES_NUM]; BLOCK_SIZE];

    for col in 0..WORD_IN_BYTES_NUM {
        for row in 0..BLOCK_SIZE {
            let x = ( ( input_state[row][col] & 0xF0 ) >> 4 ) as usize;
            let y = ( input_state[row][col] & 0x0F ) as usize;

            output_state[row][col] = INV_S_BOX[x][y];
        }
    }    

    return output_state;
}

pub fn inv_shift_rows( input_state : [[u8; WORD_IN_BYTES_NUM]; BLOCK_SIZE] ) -> [[u8; WORD_IN_BYTES_NUM]; BLOCK_SIZE] {
    let mut output_state : [[u8; WORD_IN_BYTES_NUM]; BLOCK_SIZE] = [[0; WORD_IN_BYTES_NUM]; BLOCK_SIZE];

    for row in 0..BLOCK_SIZE {
        for col in 0..WORD_IN_BYTES_NUM {
            let new_col_pos = ( col + ( WORD_IN_BYTES_NUM - row ) ) % WORD_IN_BYTES_NUM;
            output_state[row][col] = input_state[row][new_col_pos];
        }
    }

    return output_state;
}

pub fn inv_mix_columns( input_state : [[u8; WORD_IN_BYTES_NUM]; BLOCK_SIZE] ) -> [[u8; WORD_IN_BYTES_NUM]; BLOCK_SIZE] {
    let mut output_state : [[u8; WORD_IN_BYTES_NUM]; BLOCK_SIZE] = [[0; WORD_IN_BYTES_NUM]; BLOCK_SIZE];

    for col in 0..WORD_IN_BYTES_NUM {
        output_state[0][col] = multiplication( input_state[0][col], 0x0e ) ^ multiplication( input_state[1][col], 0x0b ) ^
                                multiplication( input_state[2][col], 0x0d ) ^ multiplication( input_state[3][col], 0x09 );

        output_state[1][col] = multiplication( input_state[0][col], 0x09 ) ^ multiplication( input_state[1][col], 0x0e ) ^
                                multiplication( input_state[2][col], 0x0b ) ^ multiplication( input_state[3][col], 0x0d );

        output_state[2][col] = multiplication( input_state[0][col], 0x0d ) ^ multiplication( input_state[1][col], 0x09 ) ^
                                multiplication( input_state[2][col], 0x0e ) ^ multiplication( input_state[3][col], 0x0b );

        output_state[3][col] = multiplication( input_state[0][col], 0x0b ) ^ multiplication( input_state[1][col], 0x0d ) ^
                                multiplication( input_state[2][col], 0x09 ) ^ multiplication( input_state[3][col], 0x0e );
    }

    return output_state;
}

fn multiplication( multiplicand : u8, multiplier : u8 ) -> u8 {
    let mut xtime_val : u8 = multiplicand;
    let mut result : u8 = 0;

    //check LSB
    if multiplier & 0x01 != 0 {
        result = multiplicand;
    }

    for bit_pos in 1..7 {
        if xtime_val & 0x80 != 0 {
            xtime_val = ( ( xtime_val & 0x7F ) << 1 ) ^ IRR_POLYNOMIAL;
        }
        else {
            xtime_val <<= 1;
        }
        
        if multiplier & ( 1 << bit_pos ) != 0 {
            result ^= xtime_val;
        }
    }
    
    return result;
}

pub fn sub_word( input : u32 ) -> u32 {
    let mut output : u32 = 0;

    for i in 0..WORD_IN_BYTES_NUM {
        let byte_data : u8 = ( input >> ( ( 3 - i ) * 8 ) ) as u8;
        let x = ( ( byte_data & 0xF0 ) >> 4 ) as usize;
        let y = ( byte_data & 0x0F ) as usize;

        output ^= ( S_BOX[x][y] as u32 ) << ( ( 3 - i ) * 8 );
    }

    return output;
}

pub fn rot_word( input : u32 ) -> u32 {
    let output : u32 = ( input << 8 ) | ( input >> 24 );

    return output;
}

#[test]
fn test_sub_bytes() {

    //FIPS 197 p35 C.1 AES-128 (Nk=4, Nr=10)
    let input_data = ["00102030405060708090a0b0c0d0e0f0",
                      "89d810e8855ace682d1843d8cb128fe4",
                      "4915598f55e5d7a0daca94fa1f0a63f7",
                      "fa636a2825b339c940668a3157244d17",
                      "247240236966b3fa6ed2753288425b6c",
                      "c81677bc9b7ac93b25027992b0261996",
                      "c62fe109f75eedc3cc79395d84f9cf5d",
                      "d1876c0f79c4300ab45594add66ff41f",
                      "fde3bad205e5d0d73547964ef1fe37f1",
                      "bd6e7c3df2b5779e0b61216e8b10b689"];

    let expect = ["63cab7040953d051cd60e0e7ba70e18c",
                  "a761ca9b97be8b45d8ad1a611fc97369",
                  "3b59cb73fcd90ee05774222dc067fb68",
                  "2dfb02343f6d12dd09337ec75b36e3f0",
                  "36400926f9336d2d9fb59d23c42c3950",
                  "e847f56514dadde23f77b64fe7f7d490",
                  "b415f8016858552e4bb6124c5f998a4c",
                  "3e175076b61c04678dfc2295f6a8bfc0",
                  "5411f4b56bd9700e96a0902fa1bb9aa1",
                  "7a9f102789d5f50b2beffd9f3dca4ea7"];

    for i in 0..expect.len() {
        let actual_result = state_to_text( sub_bytes( text_to_state( input_data[i].to_string() ) ) );
        assert_eq!( actual_result, expect[i] );
    }
}

#[test]
fn test_shift_rows() {

    //FIPS 197 p35 C.1 AES-128 (Nk=4, Nr=10)
    let input_data = ["63cab7040953d051cd60e0e7ba70e18c",
                      "a761ca9b97be8b45d8ad1a611fc97369",
                      "3b59cb73fcd90ee05774222dc067fb68",
                      "2dfb02343f6d12dd09337ec75b36e3f0",
                      "36400926f9336d2d9fb59d23c42c3950",
                      "e847f56514dadde23f77b64fe7f7d490",
                      "b415f8016858552e4bb6124c5f998a4c",
                      "3e175076b61c04678dfc2295f6a8bfc0",
                      "5411f4b56bd9700e96a0902fa1bb9aa1",
                      "7a9f102789d5f50b2beffd9f3dca4ea7"];

    let expect = ["6353e08c0960e104cd70b751bacad0e7",
                  "a7be1a6997ad739bd8c9ca451f618b61",
                  "3bd92268fc74fb735767cbe0c0590e2d",
                  "2d6d7ef03f33e334093602dd5bfb12c7",
                  "36339d50f9b539269f2c092dc4406d23",
                  "e8dab6901477d4653ff7f5e2e747dd4f",
                  "b458124c68b68a014b99f82e5f15554c",
                  "3e1c22c0b6fcbf768da85067f6170495",
                  "54d990a16ba09ab596bbf40ea111702f",
                  "7ad5fda789ef4e272bca100b3d9ff59f"];

    for i in 0..expect.len() {
        let actual_result = state_to_text( shift_rows( text_to_state( input_data[i].to_string() ) ) );
        assert_eq!( actual_result, expect[i] );
    }
}

#[test]
fn test_mix_columns() {

    //FIPS 197 p35 C.1 AES-128 (Nk=4, Nr=10)
    let input_data = ["6353e08c0960e104cd70b751bacad0e7",
                      "a7be1a6997ad739bd8c9ca451f618b61",
                      "3bd92268fc74fb735767cbe0c0590e2d",
                      "2d6d7ef03f33e334093602dd5bfb12c7",
                      "36339d50f9b539269f2c092dc4406d23",
                      "e8dab6901477d4653ff7f5e2e747dd4f",
                      "b458124c68b68a014b99f82e5f15554c",
                      "3e1c22c0b6fcbf768da85067f6170495",
                      "54d990a16ba09ab596bbf40ea111702f"];

    let expect = ["5f72641557f5bc92f7be3b291db9f91a",
                  "ff87968431d86a51645151fa773ad009",
                  "4c9c1e66f771f0762c3f868e534df256",
                  "6385b79ffc538df997be478e7547d691",
                  "f4bcd45432e554d075f1d6c51dd03b3c",
                  "9816ee7400f87f556b2c049c8e5ad036",
                  "c57e1c159a9bd286f05f4be098c63439",
                  "baa03de7a1f9b56ed5512cba5f414d23",
                  "e9f74eec023020f61bf2ccf2353c21c7"];

    for i in 0..expect.len() {
        let actual_result = state_to_text( mix_columns( text_to_state( input_data[i].to_string() ) ) );
        assert_eq!( actual_result, expect[i] );
    }
}

#[test]
fn test_inv_sub_bytes() {

    //FIPS 197 p35 C.1 AES-128 (Nk=4, Nr=10)
    let input_data = ["7a9f102789d5f50b2beffd9f3dca4ea7",
                      "5411f4b56bd9700e96a0902fa1bb9aa1",
                      "3e175076b61c04678dfc2295f6a8bfc0",
                      "b415f8016858552e4bb6124c5f998a4c",
                      "e847f56514dadde23f77b64fe7f7d490",
                      "36400926f9336d2d9fb59d23c42c3950",
                      "2dfb02343f6d12dd09337ec75b36e3f0",
                      "3b59cb73fcd90ee05774222dc067fb68",
                      "a761ca9b97be8b45d8ad1a611fc97369",
                      "63cab7040953d051cd60e0e7ba70e18c"];

    let expect = ["bd6e7c3df2b5779e0b61216e8b10b689",
                  "fde3bad205e5d0d73547964ef1fe37f1",
                  "d1876c0f79c4300ab45594add66ff41f",
                  "c62fe109f75eedc3cc79395d84f9cf5d",
                  "c81677bc9b7ac93b25027992b0261996",
                  "247240236966b3fa6ed2753288425b6c",
                  "fa636a2825b339c940668a3157244d17",
                  "4915598f55e5d7a0daca94fa1f0a63f7",
                  "89d810e8855ace682d1843d8cb128fe4",
                  "00102030405060708090a0b0c0d0e0f0"];

    for i in 0..expect.len() {
        let actual_result = state_to_text( inv_sub_bytes( text_to_state( input_data[i].to_string() ) ) );
        assert_eq!( actual_result, expect[i] );
    }
}

#[test]
fn test_inv_shift_rows() {

    //FIPS 197 p35 C.1 AES-128 (Nk=4, Nr=10)
    let input_data = ["7ad5fda789ef4e272bca100b3d9ff59f",
                      "54d990a16ba09ab596bbf40ea111702f",
                      "3e1c22c0b6fcbf768da85067f6170495",
                      "b458124c68b68a014b99f82e5f15554c",
                      "e8dab6901477d4653ff7f5e2e747dd4f",
                      "36339d50f9b539269f2c092dc4406d23",
                      "2d6d7ef03f33e334093602dd5bfb12c7",
                      "3bd92268fc74fb735767cbe0c0590e2d",
                      "a7be1a6997ad739bd8c9ca451f618b61",
                      "6353e08c0960e104cd70b751bacad0e7"];

    let expect = ["7a9f102789d5f50b2beffd9f3dca4ea7",
                  "5411f4b56bd9700e96a0902fa1bb9aa1",
                  "3e175076b61c04678dfc2295f6a8bfc0",
                  "b415f8016858552e4bb6124c5f998a4c",
                  "e847f56514dadde23f77b64fe7f7d490",
                  "36400926f9336d2d9fb59d23c42c3950",
                  "2dfb02343f6d12dd09337ec75b36e3f0",
                  "3b59cb73fcd90ee05774222dc067fb68",
                  "a761ca9b97be8b45d8ad1a611fc97369",
                  "63cab7040953d051cd60e0e7ba70e18c"];

    for i in 0..expect.len() {
        let actual_result = state_to_text( inv_shift_rows( text_to_state( input_data[i].to_string() ) ) );
        assert_eq!( actual_result, expect[i] );
    }
}

#[test]
fn test_inv_mix_columns() {

    //FIPS 197 p35 C.1 AES-128 (Nk=4, Nr=10)
    let input_data = ["e9f74eec023020f61bf2ccf2353c21c7",
                      "baa03de7a1f9b56ed5512cba5f414d23",
                      "c57e1c159a9bd286f05f4be098c63439",
                      "9816ee7400f87f556b2c049c8e5ad036",
                      "f4bcd45432e554d075f1d6c51dd03b3c",
                      "6385b79ffc538df997be478e7547d691",
                      "4c9c1e66f771f0762c3f868e534df256",
                      "ff87968431d86a51645151fa773ad009",
                      "5f72641557f5bc92f7be3b291db9f91a"];

    let expect = ["54d990a16ba09ab596bbf40ea111702f",
                  "3e1c22c0b6fcbf768da85067f6170495",
                  "b458124c68b68a014b99f82e5f15554c",
                  "e8dab6901477d4653ff7f5e2e747dd4f",
                  "36339d50f9b539269f2c092dc4406d23",
                  "2d6d7ef03f33e334093602dd5bfb12c7",
                  "3bd92268fc74fb735767cbe0c0590e2d",
                  "a7be1a6997ad739bd8c9ca451f618b61",
                  "6353e08c0960e104cd70b751bacad0e7"];

    for i in 0..expect.len() {
        let actual_result = state_to_text( inv_mix_columns( text_to_state( input_data[i].to_string() ) ) );
        assert_eq!( actual_result, expect[i] );
    }
}