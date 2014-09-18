/*
The MAGENTA Block Cipher (M. J. Jacobson, Jr. and K. Hubery) implementation.
http://edipermadi.files.wordpress.com/2008/09/magenta-spec.pdf
*/

use std::io::{File, IoErrorKind, EndOfFile};
use std::rand;
use std::fmt::Show;

type B8 = [u8, ..8];
type B16 = [u8, ..16];
type B24 = [u8, ..24];
type B32 = [u8, ..32];


static s_block: [u8, ..256] = [
    1, 2, 4, 8, 16, 32, 64, 128, 101, 202, 241, 135, 107, 214, 201, 247, 139,
    115, 230, 169, 55, 110, 220, 221, 223, 219, 211, 195, 227, 163, 35, 70,
    140, 125, 250, 145, 71, 142, 121, 242, 129, 103, 206, 249, 151, 75, 150,
    73, 146, 65, 130, 97, 194, 225, 167, 43, 86, 172, 61, 122, 244, 141, 127,
    254, 153, 87, 174, 57, 114, 228, 173, 63, 126, 252, 157, 95, 190, 25, 50,
    100, 200, 245, 143, 123, 246, 137, 119, 238, 185, 23, 46, 92, 184, 21, 42,
    84, 168, 53, 106, 212, 205, 255, 155, 83, 166, 41, 82, 164, 45, 90, 180,
    13, 26, 52, 104, 208, 197, 239, 187, 19, 38, 76, 152, 85, 170, 49, 98, 196,
    237, 191, 27, 54, 108, 216, 213, 207, 251, 147, 67, 134, 105, 210, 193, 231,
    171, 51, 102, 204, 253, 159, 91, 182, 9, 18, 36, 72, 144, 69, 138, 113, 226,
    161, 39, 78, 156, 93, 186, 17, 34, 68, 136, 117, 234, 177, 7, 14, 28, 56,
    112, 224, 165, 47, 94, 188, 29, 58, 116, 232, 181, 15, 30, 60, 120, 240,
    133, 111, 222, 217, 215, 203, 243, 131, 99, 198, 233, 183, 11, 22, 44, 88,
    176, 5, 10, 20, 40, 80, 160, 37, 74, 148, 77, 154, 81, 162, 33, 66, 132,
    109, 218, 209, 199, 235, 179, 3, 6, 12, 24, 48, 96, 192, 229, 175, 59, 118,
    236, 189, 31, 62, 124, 248, 149, 79, 158, 89, 178, 0
];

fn nth_byte(x: uint, n: uint) -> u8 {
    (x >> (8 * n)) as u8
}

fn nth_byte_u64(x: u64, n: uint) -> u8 {
    (x >> (8 * n)) as u8
}


fn concat_u8(a: u8, b: u8) -> u16 {
    let c: u16 = 0;
    let t_size: uint = 8;
    ((c + a as u16) << t_size) + b as u16
}

fn concat_arrays_u8(a1: &B8, a2: &B8) -> Box<B16> {
    let mut res = box [0, ..16];

    for i in range(0, 8) {
        res[i] = a1[i];
        res[i + 8] = a2[i];
    }
    res
}


fn xor_array(a1: &B8, a2: &B8) -> Box<B8> {
    let mut xa = box [0, ..8];

    for i in range(0, a1.len()) {
        xa[i] = a1[i] ^ a2[i];
    }
    xa
}


fn xor_array_16(a1: &B16, a2: &B16) -> Box<B16> {
    let mut xa = box [0, ..16];

    for i in range(0, a1.len()) {
        xa[i] = a1[i] ^ a2[i];
    }
    xa
}


fn part(n: uint, x: &[u8]) -> Box<B8> {
    let mut h = box [0, ..8];

    for i in range(0, 8) {
        h[i] = x[8 * n + i];
    }
    h
}

fn f(x: u8) -> u8 {
    s_block[x as uint]
}


fn a(x: u8, y: u8) -> u8 {
    f(x ^ f(y))
}

fn pe(x: u8, y: u8) -> u16 {
    concat_u8(a(x, y), a(y, x))
}


fn p(x: &B16) -> Box<B16> {
    let mut v = box [0, ..16];
    let mut pe_x: u16;
    let mut x1: u8;
    let mut x2: u8;

    for i in range(0, 8) {
        x1 = x[i];
        x2 = x[i + 8];
        pe_x = pe(x1, x2);
        v[i * 2] = nth_byte(pe_x as uint, 1);
        v[i * 2 + 1] = nth_byte(pe_x as uint, 0);
    }
    v
}

fn t(x: &B16) -> Box<B16> {
    p(&*p(&*p(&*p(x))))
}

fn xe(x: &B16) -> Box<B8> {
    let mut v = box [0, ..8];

    for i in range(0, 8) {
        v[i] = x[i * 2];
    }
    v
}

fn xo(x: &B16) -> Box<B8> {
    let mut v = box [0, ..8];

    for i in range(0, 8) {
        v[i] = x[i * 2 + 1];
    }
    v
}

fn c(r: uint, x: &B16) -> Box<B16> {
    if r == 1 {
        t(x)
    } else {
        let box c_prev = c(r - 1, x);
        let box c_e = xe(&c_prev);
        let box c_o = xo(&c_prev);

        let box xor1 = xor_array(&c_e, &*part(0, x));
        let box xor2 = xor_array(&c_o, &*part(1, x));
        let box x_next = concat_arrays_u8(&xor1, &xor2);
        t(&x_next)
    }
}

fn e(r: uint, x: &B16) -> Box<B8>{
    xe(&*c(r, x))
}

fn feistel_round(x: &B16, y: &B8) -> Box<B16> {
    let box x1 = part(0, x);
    let box x2 = part(1, x);
    let r = 3u;
    let box e_array = concat_arrays_u8(&x2, y);

    concat_arrays_u8(&x2, &*xor_array(&x1, &*e(r, &e_array)))
}


fn enc_128(m: &B16, k: &B16) -> Box<B16> {
    let k_parts = [part(0, k), part(1, k)];
    let mut res = box *m;
    let ks = [1u, 1, 2, 2, 1, 1];

    for ki in ks.iter() {
        res = feistel_round(&*res, &*k_parts[*ki - 1]);
    }

    res
}

fn v(x: &B16) -> Box<B16> {
    let mut vv = box [0, ..16];

    for i in range(0, 8) {
        vv[i] = x[i + 8];
        vv[i + 8] = x[i];
    }
    vv
}

fn dec_128(m: &B16, k: &B16) -> Box<B16> {
    v(&*enc_128(&*v(m), k))
}


fn enc_192(m: &B16, k: &B24) -> Box<B16> {
    let k_parts = [part(0, k), part(1, k), part(2, k)];
    let mut res = box *m;
    let ks = [1u, 2, 3, 3, 2, 1];

    for ki in ks.iter() {
        res = feistel_round(&*res, &*k_parts[*ki - 1]);
    }

    res
}

fn dec_192(m: &B16, k: &B24) -> Box<B16> {
    v(&*enc_192(&*v(m), k))
}


fn enc_256(m: &B16, k: &B32) -> Box<B16> {
    let k_parts = [part(0, k), part(1, k), part(2, k), part(3, k)];
    let mut res = box *m;
    let ks = [1u, 2, 3, 4, 4, 3, 2, 1];

    for ki in ks.iter() {
        res = feistel_round(&*res, &*k_parts[*ki - 1]);
    }

    res
}

fn dec_256(m: &B16, k: &B32) -> Box<B16> {
    v(&*enc_256(&*v(m), k))
}


fn random_fill_tail_end(buf: &mut [u8]) {
    for i in range(0, buf.len() - 1) {
        buf[i] = rand::random();
    }
    buf[buf.len() - 1] = (buf.len() - 1) as u8;
}

fn fill_with_end_bits(buf: &mut [u8]) {
    buf[0] = 64u8;
    for i in range(1, buf.len()) {
        buf[i] = 0;
    }
}

fn file_size(file: &mut File) -> u64 {
    match file.stat() {
        Err(e) => fail!("fill_with_message_len: {}", e.desc),
        Ok(s) => s.size,
    }
}

fn fill_with_file_size(file: &mut File, buf: &mut [u8]) {
    let fs: u64 = file_size(file);
    println!("file size: {}", fs);
    for i in range(0u, 8) {
        buf[buf.len() - i - 1] = nth_byte_u64(fs, i);
    }
}

fn is_file_size_can_fit(byte_count: uint, buf_len: uint) -> bool {
    buf_len - byte_count >= 8
}

fn h_file(file: &mut File) -> Box<B16> {
    let buf_len = 16;
    let h0: Box<B16> = box [0, ..16];
    let mut h = h0;
    let mut buf: [u8, ..16];
    let mut is_filled = false;
    let mut byte_count: uint = 0;

    loop {
        buf = [0, ..16];
        match file.read(buf) {
            Err(e) => {
                if e.kind == EndOfFile && is_filled {
                    break;
                } else if is_filled {
                    fail!("h_file: {}", e.desc);
                } else {
                    byte_count = 0;
                }
            },
            Ok(i) => { byte_count = i },
        };
        println!("byte_count: {}", byte_count);

        if byte_count < buf_len {
            fill_with_end_bits(buf.mut_slice_from(byte_count));

            if !is_file_size_can_fit(byte_count, buf_len) {
                h = h_func(&buf, &*h);
                buf = [0, ..16];
            }
            fill_with_file_size(file, buf);
            is_filled = true;
        }

        h = h_func(&buf, &*h);
    }

    h
}


fn h_func(buf: &B16, h: &B16) -> Box<B16> {
    let a = buf;
    let box b = xor_array_16(buf, &*h);
    let box e = enc_128(&b, a);
    let c = &b;
    xor_array_16(&e, c)
}


fn print_array(x: &[u8]) {
    print!("[");
    for xi in x.iter() {
        print!("{}, ", xi);
    }
    println!("]");
}

fn main() {
    let path = Path::new("hello.txt");
    let display = path.display();

    let mut file = match File::open(&path) {
        Err(why) => fail!("couldn't open {}: {}", display, why.desc),
        Ok(file) => file,
    };

    let box hash = h_file(&mut file);
    print_array(hash);

    // let mut buf: B16;
    // let key16: B16 = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16];
    // let key24: B24 = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
    //                   17,18,19,20,21,22,23,24];
    // let key32: B32 = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
    //                   17,18,19,20,21,22,23,24,25,26,27,28,29,
    //                   30,31,32];

    // loop {
    //     buf = [0, ..16];
    //     match file.read(buf) {
    //         Err(_) => break,
    //         _ => ()
    //     };
    //     println!("128: ");
    //     print_array(&buf);
    //     let enc_m128 = enc_128(&buf, &key16);
    //     let dec_m128 = dec_128(&*enc_m128, &key16);
    //     print_array(&*enc_m128);
    //     print_array(&*dec_m128);
    //     println!("");

    //     println!("192: ");
    //     print_array(&buf);
    //     let enc_m192 = enc_192(&buf, &key24);
    //     let dec_m192 = dec_192(&*enc_m192, &key24);
    //     print_array(&*enc_m192);
    //     print_array(&*dec_m192);
    //     println!("");

    //     println!("256: ");
    //     print_array(&buf);
    //     let enc_m256 = enc_256(&buf, &key32);
    //     let dec_m256 = dec_256(&*enc_m256, &key32);
    //     print_array(&*enc_m256);
    //     print_array(&*dec_m256);
    //     println!("");
    // }
}
