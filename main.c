#include <time.h> // for benchmark


static int Nk;  // AES key length in 32-bit words (for AES-128).
static int Nr; // Number of rounds in AES (for AES-128).

typedef unsigned char uint8_t;



// define the substitution box we later use as a lookup table
static const uint8_t Sbox[256] = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 
};



// The sbox' inverse for decrypting
static const uint8_t inverse_sbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d 
};


// an array with the rcon (rotational constants)
static const uint8_t Rotate_constants[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 
};


// MixColumns transformation matrix for mixcolumns operation
static const uint8_t mix_col_matrix[4][4] = {
    {0x02, 0x03, 0x01, 0x01},
    {0x01, 0x02, 0x03, 0x01},
    {0x01, 0x01, 0x02, 0x03},
    {0x03, 0x01, 0x01, 0x02}
};




// function to print out the block
void PrintBlock(const uint8_t block[4][4]) {
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            printf("%02x ", block[row][col]);
        }
        printf("\n");
    }
}


uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0; // accumulated product
    uint8_t hi_bit_set;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a; // if the lowest bit of b is set, XOR a into p
        hi_bit_set = a & 0x80; // check if the highest bit of a is set
        a <<= 1; // multiply a by 2 (with left bitshift)
        if (hi_bit_set) a ^= 0x1b; // if the highest bit was set, reduce modulo the AES polynomial
        b >>= 1; // divide b by 2
    }
    return p;
}



static uint8_t gmul2[256];
static uint8_t gmul3[256];
static uint8_t gmul9[256];  
static uint8_t gmul11[256]; 
static uint8_t gmul13[256]; 
static uint8_t gmul14[256]; 

void initialize_gmul_tables() {
    for (int i = 0; i < 256; i++) {
        gmul2[i] = gmul(i, 2);
        gmul3[i] = gmul(i, 3);
        gmul9[i] = gmul(i, 9);
        gmul11[i] = gmul(i, 11);
        gmul13[i] = gmul(i, 13);
        gmul14[i] = gmul(i, 14);
    }
}


void InvSubBytes(uint8_t block[4][4]) {
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            block[row][col] = inverse_sbox[block[row][col]]; // Use the inverse S-box for substitution
        }
    }
}

void InvShiftRows(uint8_t block[4][4]) {
    uint8_t temp;

    // row 1: 1-byte right shift
    temp = block[1][3];
    for (int col = 3; col > 0; col--) {
        block[1][col] = block[1][col - 1];
    }
    block[1][0] = temp;

    // row 2: 2-byte right shift
    uint8_t temp1 = block[2][3], temp2 = block[2][2];
    block[2][3] = block[2][1];
    block[2][2] = block[2][0];
    block[2][1] = temp1;
    block[2][0] = temp2;

    // row 3: 3-byte right shift
    temp = block[3][0];
    for (int col = 0; col < 3; col++) {
        block[3][col] = block[3][col + 1];
    }
    block[3][3] = temp;
}


void InvMixColumns(uint8_t block[4][4]) {
    uint8_t temp[4];

    for (int col = 0; col < 4; col++) {
        temp[0] = gmul14[block[0][col]] ^ gmul11[block[1][col]] ^ gmul13[block[2][col]] ^ gmul9[block[3][col]];
        temp[1] = gmul9[block[0][col]] ^ gmul14[block[1][col]] ^ gmul11[block[2][col]] ^ gmul13[block[3][col]];
        temp[2] = gmul13[block[0][col]] ^ gmul9[block[1][col]] ^ gmul14[block[2][col]] ^ gmul11[block[3][col]];
        temp[3] = gmul11[block[0][col]] ^ gmul13[block[1][col]] ^ gmul9[block[2][col]] ^ gmul14[block[3][col]];

        // write the result back to the block
        for (int row = 0; row < 4; row++) {
            block[row][col] = temp[row];
        }
    }
}




// function to xor round key with block (column wise)
void AddRoundKey(uint8_t block[4][4], const uint8_t* round_key, int round) {    
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            block[col][row] ^= round_key[(round * 16) + (row * 4) + col];
        }
    }
}




// function to shift rows in block
void ShiftRows(uint8_t block[4][4]) {
    uint8_t temp;

    // row 1: 1-byte left shift
    temp = block[1][0];
    for (int col = 0; col < 3; col++) {
        block[1][col] = block[1][col + 1];
    }
    block[1][3] = temp;

    // row 2: 2-byte left shift
    uint8_t temp1 = block[2][0], temp2 = block[2][1];
    block[2][0] = block[2][2];
    block[2][1] = block[2][3];
    block[2][2] = temp1;
    block[2][3] = temp2;

    // row 3: 3-byte left shift
    temp = block[3][3];
    for (int col = 3; col > 0; col--) {
        block[3][col] = block[3][col - 1];
    }
    block[3][0] = temp;
}



void key_expand(uint8_t key[], uint8_t output[]) {
    unsigned i, j, k;
    uint8_t tempa[4];

    // Step 1: Copy the original key to the start of the output array.
    for (i = 0; i < Nk * 4; ++i) {
        output[i] = key[i];
    }

    // Step 2: Expand the key.
    for (i = Nk; i < 4 * (Nr + 1); ++i) {
        k = (i - 1) * 4;
        tempa[0] = output[k + 0];
        tempa[1] = output[k + 1];
        tempa[2] = output[k + 2];
        tempa[3] = output[k + 3];

        // Apply the key expansion schedule for words multiple of Nk
        if (i % Nk == 0) {
            uint8_t temp = tempa[0];
            tempa[0] = Sbox[tempa[1]] ^ Rotate_constants[i / Nk];  // Apply Sbox and Rcon
            tempa[1] = Sbox[tempa[2]];
            tempa[2] = Sbox[tempa[3]];
            tempa[3] = Sbox[temp];
        }

        // If Nk = 8, and i is a multiple of 8, we also apply a special transformation (2nd round of S-box)
        if (Nk == 8 && i % Nk == 4) {
            tempa[0] = Sbox[tempa[0]];
            tempa[1] = Sbox[tempa[1]];
            tempa[2] = Sbox[tempa[2]];
            tempa[3] = Sbox[tempa[3]];
        }

        // Step 3: XOR with the word from Nk positions earlier.
        for (j = 0; j < 4; ++j) {
            output[i * 4 + j] = output[(i - Nk) * 4 + j] ^ tempa[j];
        }
    }
}




// the main logic that encrypts a 16 byte 4x4 block 
void AES_Encrypt(uint8_t block[4][4], const uint8_t* expanded_key) {

    // xor the first initial round key with the block  (round key 0) 
    AddRoundKey(block, expanded_key, 0); 
    int round;
    // 9 Main rounds (excluding the final)
    for (round = 1; round <= (Nr - 1); round++) {
        // substitute bytes
        for (int row = 0; row < 4; row++) {
            for (int col = 0; col < 4; col++) {
                block[row][col] = Sbox[block[row][col]];
            }
        }
        // shift rows
        ShiftRows(block);
        // mix columns
        uint8_t temp[4];
        for (int col = 0; col < 4; col++) {
            // perform matrix multiplication for each column using precomputed gmul tables
            temp[0] = gmul2[block[0][col]] ^ gmul3[block[1][col]] ^ block[2][col] ^ block[3][col];
            temp[1] = block[0][col] ^ gmul2[block[1][col]] ^ gmul3[block[2][col]] ^ block[3][col];
            temp[2] = block[0][col] ^ block[1][col] ^ gmul2[block[2][col]] ^ gmul3[block[3][col]];
            temp[3] = gmul3[block[0][col]] ^ block[1][col] ^ block[2][col] ^ gmul2[block[3][col]];

            // write the result back to the block
            for (int row = 0; row < 4; row++) {
                block[row][col] = temp[row];
            }
        }

        // and finally add the round key
        AddRoundKey(block, expanded_key, round);

    }

    // final round adding round key 10 (no MixColumns)
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            block[row][col] = Sbox[block[row][col]];
        }
    }
    ShiftRows(block);
    AddRoundKey(block, expanded_key, round);
}

//uint8_t prepare_blocks(){} // from hex / byte array to the block or multiple blocks


void AES_Decrypt(uint8_t block[4][4], const uint8_t* expanded_key) {
    // XOR the last round key with the block
    AddRoundKey(block, expanded_key, Nr); // No inverse function because xor a ^ b = c, c ^ b = a, c ^ a = b
    InvShiftRows(block);
    InvSubBytes(block);

    // 9 Main rounds (excluding the final)
    for (int round = Nr - 1; round >= 1; round--) {

        AddRoundKey(block, expanded_key, round);
        InvMixColumns(block);
        InvShiftRows(block);
        InvSubBytes(block);

    }

    AddRoundKey(block, expanded_key, 0);
}






void ECB_mode(uint8_t block[4][4], uint8_t key[], int e_d) {
    int expanded_key_size =  4 * (Nr + 1) * 4; // words_in_block * (rounds + 1) * 4
    uint8_t expandedKey[expanded_key_size];
    key_expand(key, expandedKey);

      for (int i = 0; i < expanded_key_size; i++) {
            printf("%02x ", expandedKey[i]);
            if (((i+1) % 16) == 0) {
                printf("\n");
            } 
        }


    if (e_d == 1){
        clock_t start = clock();
        for(int black = 0; black < 10*65536; black++) {
            AES_Encrypt(block, expandedKey); // no plaintext because the plaintext is already in the block
        }
        clock_t end = clock();
        float elapsed = (end - start) / CLOCKS_PER_SEC;
        printf("%f", elapsed);

    } else {
        AES_Decrypt(block, expandedKey);
    }
}









int main() { 

    // here we define the key and others, since the code is still in development an example will be used.
    // The code supports multiple blocks however we will just use one of the NIST standard. More info about that below
    
    int E_D = 1; // e_d is for encryption or decryption mode. When e_d = 1 encryption mode is enabled, otherwise its decryption
    int amount = 1; /* we only use one block in this example, when using this with the blocks var the compiler will say that you 
    cannot initialize a variable-sized object except with an empty initializer. This var will only work when the main function is called with the amount as argument
    since this is not the case right now and this code is a proof of concept we will not use it for the blocks var size*/
    uint8_t key[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};//,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    
    
    // IMPORTANT : the block should be rotated Column wise. So if you want to set the first to bytes of the block (e.g ffaa)
    // ff would be in [0][0] and the next byte aa would be in [1][0] instead of [0][1]. Not using this column wise method will completely change your output.
    uint8_t blocks[1][4][4] =      {{{0x80, 0x00, 0x00, 0x00},
                                    {0x00, 0x00, 0x00, 0x00},
                                    {0x00, 0x00, 0x00, 0x00},
                                    {0x00, 0x00, 0x00, 0x00}}};


    //uint8_t iv[16]; // not used in ecb mode
    uint8_t temp_block[16*amount];
    int aes_bits = 128; // specifically for this example, can be changed to 256/192 anytime
    int mode = 1; // ecb mode, later when more modes will be added this will have its functionality

    

    // The following code is only needed when using arguments to the main function


    /*
    memcpy(key, key_array, 32 * sizeof(uint8_t));
    memcpy(temp_block, block_array, 16 * sizeof(uint8_t) * amount); // Assuming `blocks_array` is 16 bytes
    memcpy(iv, iv_array, 16 * sizeof(uint8_t));

    for (int blck = 0; blck < amount; blck++) {
        for (int i = 0; i < 4; i++) {  // Loop over rows
            for (int j = 0; j < 4; j++) {  // Loop over columns
                blocks[blck][i][j] = temp_block[i * 4 + j + (blck * 16)];  // Row-major order copying
            }
        }
    }

    */


    initialize_gmul_tables();

    if (aes_bits == 128) {
        Nk = 4;
        Nr = 10;
    } if (aes_bits == 192) {
        Nk = 6;
        Nr = 12;
    } if (aes_bits == 256) {
        Nk = 8;
        Nr = 14;
    }


    if (mode == 1) {
        for (int blck = 0; blck < amount; blck++) {
            ECB_mode(blocks[blck], key, E_D); // eventually input "blocks" with for loop
        }
    }
    
    // print every block 
    for (int blck = 0; blck < amount; blck++) {
        printf("BLOCK %d ------------------------------------\n", blck);
        PrintBlock(blocks[blck]);
    }
    
    return 0;
}



// THIS IS A TEST VECTOR FROM THE OFFICIAL NIST (AESVS VarTxt test data for ECB / AES Known Answer Test (KAT) Vectors)
// https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Block-Ciphers
//KEY = 00000000000000000000000000000000
//PLAINTEXT = 80000000000000000000000000000000
//CIPHERTEXT = 3ad78e726c1ec02b7ebfe92b23d9ec34 voor 128-bits en ddc6bf790c15760d8d9aeb6f9a75fd4e voor 256-bits