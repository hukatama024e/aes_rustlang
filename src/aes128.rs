use hex;

const WORD_IN_BYTES_NUM : usize = 4;
const BLOCK_SIZE : usize = 4;
const ROUND_NUM : usize = 10;
const KEY_LENGTH : usize = 4;

// Irreducible polynomial(0x11B) to 8bit
// When XOR calculation, MSB translate to 0. So 0x11B can translate to 0x1B in 8bit valiable calculation
const IRR_POLYNOMIAL : u8 = 0x1B;

const S_BOX : [[u8; 16]; 16] = [
    [  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76  ],
    [  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0  ],
    [  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15  ],
    [  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75  ],
    [  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84  ],
    [  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf  ],
    [  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8  ],
    [  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2  ],
    [  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73  ],
    [  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb  ],
    [  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79  ],
    [  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08  ],
    [  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a  ],
    [  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e  ],
    [  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf  ],
    [  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16  ]
];

const R_CON : [u8; 10] = [ 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 ];

pub fn cipher( plain_text : String, round_key : [u32; BLOCK_SIZE * ( ROUND_NUM + 1 )] ) -> String {
    let mut state : [[u8; WORD_IN_BYTES_NUM]; BLOCK_SIZE] = text_to_state( plain_text );
    let encrypted_text : String;

    state = add_round_key( state, round_key, 0 );

    for round in 1..ROUND_NUM - 1 {
        state = sub_bytes( state );
        state = shift_rows( state );
        state = mix_columns( state );
        state = add_round_key( state, round_key, round );
    }

    state = sub_bytes( state );
    state = shift_rows( state );
    state = add_round_key( state, round_key, ROUND_NUM );

    encrypted_text = state_to_text( state );

    return encrypted_text;
}

fn text_to_state( text : String ) -> [[u8; WORD_IN_BYTES_NUM]; BLOCK_SIZE] {
    let mut state : [[u8; WORD_IN_BYTES_NUM]; BLOCK_SIZE] = [[0; WORD_IN_BYTES_NUM]; BLOCK_SIZE];

    // check text length
    assert!( text.len() == BLOCK_SIZE * WORD_IN_BYTES_NUM * 2 );

    let hex_data = hex::decode( text ).expect( "Failed decoding text to state" );

    for col in 0..WORD_IN_BYTES_NUM {
        for row in 0..BLOCK_SIZE {
            state[row][col] = hex_data[row + WORD_IN_BYTES_NUM * col ];
        }
    }

    return state;
}

fn state_to_text( state : [[u8; WORD_IN_BYTES_NUM]; BLOCK_SIZE] ) -> String {
    let mut hex_data : Vec<u8> = vec![0; BLOCK_SIZE * WORD_IN_BYTES_NUM];

    for col in 0..WORD_IN_BYTES_NUM {
        for row in 0..BLOCK_SIZE {
            hex_data[row + WORD_IN_BYTES_NUM * col ] = state[row][col];
        }
    }

    let text = hex::encode( hex_data );

    return text;
}

fn sub_bytes( input_state : [[u8; WORD_IN_BYTES_NUM]; BLOCK_SIZE] ) -> [[u8; WORD_IN_BYTES_NUM]; BLOCK_SIZE] {
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

fn shift_rows( input_state : [[u8; WORD_IN_BYTES_NUM]; BLOCK_SIZE] ) -> [[u8; WORD_IN_BYTES_NUM]; BLOCK_SIZE] {
    let mut output_state : [[u8; WORD_IN_BYTES_NUM]; BLOCK_SIZE] = [[0; WORD_IN_BYTES_NUM]; BLOCK_SIZE];

    for row in 0..BLOCK_SIZE {
        for col in 0..WORD_IN_BYTES_NUM {
            let new_col_pos = ( col + row ) % WORD_IN_BYTES_NUM;
            output_state[row][col] = input_state[row][new_col_pos];
        }
    }

    return output_state;
}

fn mix_columns( input_state : [[u8; WORD_IN_BYTES_NUM]; BLOCK_SIZE] ) -> [[u8; WORD_IN_BYTES_NUM]; BLOCK_SIZE] {
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

fn add_round_key( input_state : [[u8; WORD_IN_BYTES_NUM]; BLOCK_SIZE], round_key : [u32; BLOCK_SIZE * ( ROUND_NUM + 1 )], round : usize ) -> [[u8; WORD_IN_BYTES_NUM]; BLOCK_SIZE] {
    let mut output_state : [[u8; WORD_IN_BYTES_NUM]; BLOCK_SIZE] = [[0; WORD_IN_BYTES_NUM]; BLOCK_SIZE];

    for col in 0..WORD_IN_BYTES_NUM {
        output_state[0][col] = input_state[0][col] ^ ( ( round_key[round * BLOCK_SIZE + col] >> 24 & 0x000000FF ) as u8 );
        output_state[1][col] = input_state[1][col] ^ ( ( round_key[round * BLOCK_SIZE + col] >> 16 & 0x000000FF ) as u8 );
        output_state[2][col] = input_state[2][col] ^ ( ( round_key[round * BLOCK_SIZE + col] >> 8 & 0x000000FF ) as u8 );
        output_state[3][col] = input_state[3][col] ^ ( ( round_key[round * BLOCK_SIZE + col] & 0x000000FF ) as u8 );
    }

    return output_state;
}

fn multiplication( multiplicand : u8, multiplier : u8 ) -> u8 {
    let mut xtime_val : u8 = multiplicand;
    let mut result : u8 = 0;

    for bit_pos in 1..8 {
        if xtime_val & 0x80 != 0 {
            xtime_val = ( ( xtime_val & 0x7F ) << 1 ) ^ IRR_POLYNOMIAL;
        }
        else {
            xtime_val <<= 1;
        }
        
        if ( 1 << bit_pos ) & multiplier != 0 {
            result ^= xtime_val;
        }
    }
    
    return result;
}

pub fn key_expansion( key : [u8; 4 * KEY_LENGTH] ) ->  [u32; BLOCK_SIZE*( ROUND_NUM + 1 )] {
    let mut round_key : [u32; BLOCK_SIZE * ( ROUND_NUM + 1 )] = [0; BLOCK_SIZE * ( ROUND_NUM + 1 )];
    let mut i : usize = 0;
    let mut temp : u32;

    while i < KEY_LENGTH {
        round_key[i] = ( key[ i * 4] as u32 ) << 24 &
                        ( key[ i * 4 + 1] as u32 ) << 16 & 
                        ( key[ i * 4 + 2] as u32 ) << 8 &
                        ( key[ i * 4 + 3] as u32 );
        i += 1;
    }

    i = KEY_LENGTH;

    while i < BLOCK_SIZE * ( ROUND_NUM + 1 ) {
        temp = round_key[i - 1];

        if i % KEY_LENGTH == 0 {
            temp = sub_word( rot_word( temp ) ) ^ ( ( R_CON[i / KEY_LENGTH - 1] as u32 ) << 24 );
        }

        round_key[i] = round_key[i - KEY_LENGTH] ^ temp;
        i += 1;
    }

    return round_key;
}

fn sub_word( input : u32 ) -> u32 {
    let mut output : u32 = 0;

    for i in 0..3 {
        let byte_data : u8 = ( input >> ( ( 3 - i ) * 8 ) ) as u8;
        let x = ( ( byte_data & 0xF0 ) >> 4 ) as usize;
        let y = ( byte_data & 0x0F ) as usize;

        output ^= ( S_BOX[x][y] as u32  ) << ( ( 3 - i ) * 8 );
    }

    return output;
}

fn rot_word( input : u32 ) -> u32 {
    let output : u32 = ( input >> 8 ) & ( input >> 24 );

    return output;
}