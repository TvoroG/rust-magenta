use std::io::{File};
use std::rand;
use num::bigint::BigUint;
use std::num::{One, Zero};

pub type B8 = [u8, ..8];
pub type B16 = [u8, ..16];
pub type B24 = [u8, ..24];
pub type B32 = [u8, ..32];


pub fn nth_byte(x: uint, n: uint) -> u8 {
    (x >> (8 * n)) as u8
}

pub fn nth_byte_u64(x: u64, n: uint) -> u8 {
    (x >> (8 * n)) as u8
}

pub fn slice_to_u64(slice: &[u8]) -> u64 {
    let mut res: u64 = 0;
    let mut b: u64;
    for (i, byte) in slice.iter().enumerate() {
        b = byte.clone() as u64;
        res += b << (slice.len() * 8 - (i + 1) * 8);
    }
    res
}


pub fn concat_u8(a: u8, b: u8) -> u16 {
    let c: u16 = 0;
    let t_size: uint = 8;
    ((c + a as u16) << t_size) + b as u16
}

pub fn concat_arrays_u8(a1: &B8, a2: &B8) -> Box<B16> {
    let mut res = box [0, ..16];

    for i in range(0, 8) {
        res[i] = a1[i];
        res[i + 8] = a2[i];
    }
    res
}


pub fn xor_array(a1: &B8, a2: &B8) -> Box<B8> {
    let mut xa = box [0, ..8];

    for i in range(0, a1.len()) {
        xa[i] = a1[i] ^ a2[i];
    }
    xa
}


pub fn xor_array_16(a1: &B16, a2: &B16) -> Box<B16> {
    let mut xa = box [0, ..16];

    for i in range(0, a1.len()) {
        xa[i] = a1[i] ^ a2[i];
    }
    xa
}


pub fn part(n: uint, x: &[u8]) -> Box<B8> {
    let mut h = box [0, ..8];

    for i in range(0, 8) {
        h[i] = x[8 * n + i];
    }
    h
}


pub fn random_fill_tail_end(buf: &mut [u8]) {
    for i in range(0, buf.len() - 1) {
        buf[i] = rand::random();
    }
    buf[buf.len() - 1] = (buf.len() - 1) as u8;
}

pub fn fill_with_end_bits(buf: &mut [u8]) {
    buf[0] = 64u8;
    for i in range(1, buf.len()) {
        buf[i] = 0;
    }
}

pub fn file_size(file: &mut File) -> u64 {
    match file.stat() {
        Err(e) => fail!("fill_with_message_len: {}", e.desc),
        Ok(s) => s.size,
    }
}

pub fn fill_with_file_size(file: &mut File, buf: &mut [u8]) {
    let fs: u64 = file_size(file);
    println!("file size: {}", fs);
    for i in range(0u, 8) {
        buf[buf.len() - i - 1] = nth_byte_u64(fs, i);
    }
}

pub fn is_file_size_can_fit(byte_count: uint, buf_len: uint) -> bool {
    buf_len - byte_count >= 8
}

pub fn get_original_size(block: &B16) -> u64 {
    slice_to_u64(block.slice_from(block.len() - 8))
}

pub fn mod_pow(num: BigUint, exp: BigUint, m: BigUint) -> BigUint {
    let one: BigUint = One::one();

    if m.is_zero() { fail!("non-positive modulo"); }
    if exp == one { return exp % m; }

    let mut s = one.clone();
    let mut t = num.clone();
    let mut u = exp.clone();

    while !u.is_zero() {
        if u & one == one {
            s = s * t % m;
        }
        u = u >> 1u;
        t = t * t % m;
    }
    s
}

pub fn print_array(x: &[u8]) {
    print!("[");
    for xi in x.iter() {
        print!("{}, ", xi);
    }
    println!("]");
}
