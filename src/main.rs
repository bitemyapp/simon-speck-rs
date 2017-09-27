extern crate byteorder;

// -------------------------- definitions --------------------------
// n = word size (16, 24, 32, 48, or 64)
// m = number of key words (must be 4 if n = 16,
// 3 or 4 if n = 24 or 32,
// 2 or 3 if n = 48,
// 2, 3, or 4 if n = 64)
// z = [11111010001001010110000111001101111101000100101011000011100110,
// 10001110111110010011000010110101000111011111001001100001011010,
// 10101111011100000011010010011000101000010001111110010110110011,
// 11011011101011000110010111100000010010001010011100110100001111,
// 11010001111001101011011000100000010111000011001010010011101111]
// (T, j) = (32,0) if n = 16
// = (36,0) or (36,1) if n = 24, m = 3 or 4
// = (42,2) or (44,3) if n = 32, m = 3 or 4
// = (52,2) or (54,3) if n = 48, m = 2 or 3
// = (68,2), (69,3), or (72,4) if n = 64, m = 2, 3, or 4
// x,y = plaintext words
// k[m-1]..k[0] = key words
// ------------------------- key expansion -------------------------
// for i = m..T-1
// tmp ← S
// −3 k[i-1]
// if (m = 4) tmp ← tmp ⊕ k[i-3]
// tmp ← tmp ⊕ S
// −1tmp
// k[i] ← ~k[i-m] ⊕ tmp ⊕ z[j][(i-m) mod 62] ⊕ 3
// end for
// -------------------------- encryption ---------------------------
// for i = 0..T-1
// tmp ← x
// x ← y ⊕ (Sx & S
// 8x) ⊕ S
// 2x ⊕ k[i]
// y ← tmp
// end for

// fn encryption(n: u32, t: u8, k: [u16; 32], mut x: u16, mut y: u16) -> (u16, u16) {
//     for i in 0..(t-1) {
//         let tmp = x.clone();
//         // let x = y `xor` (Sx & S8x) `xor` S2x `xor` k[i];
//         // x = y ^ (x.rotate_left(1) & x.rotate_left(8)) ^ x.rotate_left(2) ^ k[i as usize];
//         x = y ^ (x.rotate_left(1) & x.rotate_left(8)) ^ x.rotate_left(2) ^ k[i as usize];
//         y = tmp;
//     }
//     (x, y)
// }

use std::io::Cursor;
// use std::iter;
use byteorder::{BigEndian, LittleEndian, ReadBytesExt};

fn key_expansion(j: u8, z: [u64; 5], m: u8, t: u8, mut k: [u16; 32]) -> [u16; 32] {
    for i in m..(t-1) {
    // for i in (m..(t-1)).rev() {

    // for i in (t-1)..m {
        // let tmp = S-3 k[i-1]
        let mut tmp: u16 = k[(i-1) as usize].rotate_right(3);
        // if (m == 4) { let tmp = tmp `xor` k[i-3]
        if (m == 4) {
            tmp = tmp ^ k[(i-3) as usize]
        }
        // let tmp = tmp `xor` s-1 tmp
        tmp = tmp ^ tmp.rotate_right(1);
        // k[i] = !k[i-m] `xor` tmp `xor` z[j][(i-m) `mod` 62] `xor` 3
        let idx = (i - m) % 62;
        k[i as usize] = !k[(i-m) as usize] ^ tmp ^ (bit_idx(z[j as usize], idx as u64, (idx+1) as u64) as u16) ^ 3;
    }
    k
}

fn encryption(t: u8, k: [u16; 32], mut x: u16, mut y: u16) -> (u16, u16) {
    // for i in 0..(t-1) {
    for i in (0..(t-1)).rev() {

        let tmp = x.clone();
        // let x = y `xor` (Sx & S8x) `xor` S2x `xor` k[i];
        x = y ^ (x.rotate_left(1) & x.rotate_left(8)) ^ x.rotate_left(2) ^ k[i as usize];
        y = tmp;
    }
    (x, y)
}

fn decryption(t: u8, k: [u16; 32], mut x: u16, mut y: u16) -> (u16, u16) {
    // for i in 0..(t-1) {
    for i in (0..(t-1)) {

        // let tmp = x.clone();
        // // let x = y `xor` (Sx & S8x) `xor` S2x `xor` k[i];
        // x = y ^ (x.rotate_left(1) & x.rotate_left(8)) ^ x.rotate_left(2) ^ k[i as usize];
        // y = tmp;
        let tmp = y.clone();
        y = x ^ (y.rotate_left(1) & y.rotate_left(8)) ^ y.rotate_left(2) ^ k[i as usize];
        x = tmp;
    }
    (x, y)
}

fn create_mask(a: u64, b: u64) -> u64 {
    let mut r: u64 = 0;
    for i in a..b {
        r |= 1 << i;
    }
    r
}

fn bit_idx(byte: u64, i: u64, j: u64) -> u64 {
    byte & create_mask(i, j)
}

// n = 16
// m = 4
// T = 32
// j = 0
// k[3..0]

fn main() {
    let z: [u64; 5] =
        [0b11111010001001010110000111001101111101000100101011000011100110,
         0b10001110111110010011000010110101000111011111001001100001011010,
         0b10101111011100000011010010011000101000010001111110010110110011,
         0b11011011101011000110010111100000010010001010011100110100001111,
         0b11010001111001101011011000100000010111000011001010010011101111];
    // println!("0b{:62b}", z[0]);
    // println!("{:?}", z[0]);

    let n = 16;
    let m = 4;
    let j = 0;
    let t = 32;
    let mut key: u64 = 0x1918_1110_0908_0100;
    // let mut k: [u16; 4] = [0x1918, 0x1110, 0x0908, 0x0100];
    let mut k: [u16; 32] =
        [0x1918, 0x1110, 0x0908, 0x0100,
         0, 0, 0, 0,
         0, 0, 0, 0,
         0, 0, 0, 0,
         0, 0, 0, 0,
         0, 0, 0, 0,
         0, 0, 0, 0,
         0, 0, 0, 0];

    // println!("{:?}", k);

    let x: u16 = 0x6565;
    let y: u16 = 0x6877;
    // j: u8, z: [u64; 5], m: u8, t: u8, mut k: [u16; 4]) -> [u16; 4] {
    let new_key = key_expansion(j, z, m, t, k);
    // println!("Key");
    // println!("{:?}", key);
    // println!("new_key");
    // println!("{:?}", new_key);
    // (t: u8, k: [u16; 32], x: u16, y: u16) -> (u16, u16) {
    let (c_x, c_y) = encryption(t, new_key, x, y);
    println!("plain text");
    println!("{:x} {:x}", x, y);

    println!("cipher text");
    println!("{:x} {:x}", c_x, c_y);

    let (d_x, d_y) = decryption(t, new_key, c_x, c_y);
    println!("decrypted text");
    println!("{:x} {:x}", d_x, d_y);

    if (c_x, c_y) == (0xc69b, 0xe9bb) {
        println!("YO THIS MIGHT BE CORRECT");
    }
    let mut rdr = Cursor::new(vec![2, 5, 3, 0]);
    println!("{:?}", rdr.read_u16::<BigEndian>().unwrap());
    println!("{:?}", rdr.read_u16::<BigEndian>().unwrap());

    // let mut rdr = Cursor::new(vec![0xc69b, 0xe9bb]);
    // let mut rdr = Cursor::new(vec![0x9b, 0xc6, 0xbb, 0xe9]);
    // println!("{:?}", rdr.read_u16::<LittleEndian>().unwrap());
    // println!("{:?}", rdr.read_u16::<LittleEndian>().unwrap());

    // let mut rdr = Cursor::new(vec![0xc6, 0x9b, 0xe9, 0xbb]);
    // println!("{:?}", rdr.read_u16::<BigEndian>().unwrap());
    // println!("{:?}", rdr.read_u16::<BigEndian>().unwrap());

    // let mut rdr = Cursor::new(vec![0xc6, 0x9b, 0xe9, 0xbb]);
    // let mut rdr = Cursor::new(vec![0x9b, 0xc6, 0xbb, 0xe9]);
    // let mut rdr = Cursor::new(vec![0x19, 0xf1, 0xfe, 0x9c]);
    // println!("{:?}", rdr.read_u16::<BigEndian>().unwrap());
    // println!("{:?}", rdr.read_u16::<BigEndian>().unwrap());

    // println!("{:?}", vec![0x9b, 0xc6, 0xbb, 0xe9]);
    // println!("{:?}", vec![0xc69b, 0xe9bb]);

    // println!("{:?}", rdr.read_u8().unwrap());
    // println!("{:?}", rdr.read_u8().unwrap());

    // println!("{:?}", rdr.read_u16::<LittleEndian>().unwrap());

    // assert_eq!(517, rdr.read_u16::<BigEndian>().unwrap());
    // assert_eq!(768, rdr.read_u16::<BigEndian>().unwrap());
    // for n in 0..16 {
    //     let (c_x, c_y) = encryption(n, t, new_key, x, y);
    //     println!("plain text");
    //     println!("{:x} {:x}", x, y);

    //     println!("cipher text");
    //     println!("{:x} {:x}", c_x, c_y);
    // }

    // let plain_text: &str = "65656877";
    // println!("0x{:x}", key);
    // println!("0x{:x}", key | 0b0010);
    // println!("0x{:x}", key >> 2);
    // println!("0x{:x}", key << 2);
    // println!("0x{:x}", key ^ 0b0001);
    // let mut byte: u64 = 0b0111_0101;
    // println!("0b{:08b}", bit_idx(byte, 0, 1));
    // let j = 0;
    // for i in 0..16 {
    //     println!("0b{:08b}", bit_idx(z[j as usize], i as u64, (i+1) as u64));
    // }
    
    // let mut byte: u64 = 0b0111_0101;
    // println!("0b{:08b}", byte.rotate_left(1));
    // // println!("0b{:08b}", byte.rotate_left(-1));
    // println!("0b{:08b}", byte.rotate_right(1));
    // println!("0b{:08b}", byte.rotate_right(-1));

    // let mut n: u32 = 0;
    // loop {
    //     let mut byte: u8 = 0b0000_0001;
    //     // println!("0b{:08b}", byte << n);
    //     println!("0b{:08b}", byte.rotate_left(n));
    //     n += 1;
    // }

    // println!("0b{:08b}", byte);
    // byte |= 0b0000_1000; // Set a bit
    // println!("0b{:08b}", byte);
    // byte &= 0b1111_0111; // Unset a bit
    // println!("0b{:08b}", byte);

    // byte ^= 0b0000_1000; // Toggle a bit
    // println!("0b{:08b}", byte);
}

// Simon32/64
// Key: 1918 1110 0908 0100
// Plaintext: 6565 6877
// Ciphertext: c69b e9bb
// Simon48/72
// Key: 121110 0a0908 020100
// Plaintext: 612067 6e696c
// Ciphertext: dae5ac 292cac
// Simon48/96
// Key: 1a1918 121110 0a0908 020100
// Plaintext: 726963 20646e
// Ciphertext: 6e06a5 acf156
// Simon64/96
// Key: 13121110 0b0a0908 03020100
// Plaintext: 6f722067 6e696c63
// Ciphertext: 5ca2e27f 111a8fc8
// Simon64/128
// Key: 1b1a1918 13121110 0b0a0908 03020100
// Plaintext: 656b696c 20646e75
// Ciphertext: 44c8fc20 b9dfa07a
// Simon96/96
// Key: 0d0c0b0a0908 050403020100
// Plaintext: 2072616c6c69 702065687420
// Ciphertext: 602807a462b4 69063d8ff082
// Simon96/144
// Key: 151413121110 0d0c0b0a0908 050403020100
// Plaintext: 746168742074 73756420666f
// Ciphertext: ecad1c6c451e 3f59c5db1ae9
// Simon128/128
// Key: 0f0e0d0c0b0a0908 0706050403020100
// Plaintext: 6373656420737265 6c6c657661727420
// Ciphertext: 49681b1e1e54fe3f 65aa832af84e0bbc
// Simon128/192
// Key: 1716151413121110 0f0e0d0c0b0a0908 0706050403020100
// Plaintext: 206572656874206e 6568772065626972
// Ciphertext: c4ac61effcdc0d4f 6c9c8d6e2597b85b
// Simon128/256
// Key: 1f1e1d1c1b1a1918 1716151413121110 0f0e0d0c0b0a0908 0706050403020100
// Plaintext: 74206e69206d6f6f 6d69732061207369
// Ciphertext: 8d2b5579afc8a3a0 3bf72a87efe7b868
