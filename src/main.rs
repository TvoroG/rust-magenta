/*
The MAGENTA Block Cipher (M. J. Jacobson, Jr. and K. Hubery) implementation.
http://edipermadi.files.wordpress.com/2008/09/magenta-spec.pdf
*/
extern crate getopts;
extern crate magenta;

use std::io::{File, IoErrorKind, EndOfFile, IoResult};
use std::fmt::Show;
use std::os;
use std::default::Default;
use getopts::{optopt,optflag,getopts,OptGroup};
use magenta::pbc::PBC;
use magenta::ds::DigSig;
use magenta::hash::h_file;
use magenta::utils::print_array;


fn print_usage(program: &str, opts: &[OptGroup]) {
    println!("Usage: {} pbc [-k|--key path] <input_file> <output_file>", program);
    println!("Usage: {} pbc <-d|--dec> <-k|--key path> <input_file> <output_file>", program);
    println!("       {} hash <input_file>", program);
    println!("       {} ds [-k|--key path] <input_file>", program);
    println!("       {} ds <-v|--verify sig> <-k|--key path> <input_file>", program);
    println!("");
    for opt in opts.iter() {
        println!("-{}, --{}\t{}", opt.short_name, opt.long_name, opt.desc);
    }
}


fn main() {
    let args: Vec<String> = os::args();

    let program = args[0].clone();

    let opts = [
        optflag("h", "help", "print this help menu"),
        optflag("d", "dec", "decrypt file"),
        optopt("k", "key", "key file", "hint"),
        optopt("v", "verify", "verify signature of file", "hint"),
    ];

    let matches = match getopts(args.tail(), opts) {
        Ok(m) => { m }
        Err(f) => { fail!(f.to_string()) }
    };


    if matches.opt_present("h") {
        print_usage(program.as_slice(), &opts);
        return;
    }

    let command = match matches.free.get(0).as_slice() {
        c @ "pbc" | c @ "hash" | c @ "ds" => c,
        _ => {
            print_usage(program.as_slice(), &opts);
            return;
        }
    };

    let free_len = matches.free.len();
    match command {
        "pbc" if free_len == 3 => {
            let path_in_str = matches.free.get(1);
            let path_in = Path::new(path_in_str.as_slice());
            let path_out = Path::new(matches.free.get(2).as_slice());

            let mut file_in = File::open(&path_in).unwrap();
            let mut file_out = File::create(&path_out).unwrap();

            let key_file = match matches.opt_str("k") {
                Some(k) => k,
                None if !matches.opt_present("d") => {
                    let mut private_key_path = path_in_str.clone();
                    private_key_path.push_str(".pk");
                    PBC::rnd_key(private_key_path.as_slice());
                    private_key_path
                },
                _ => {
                    print_usage(program.as_slice(), &opts);
                    return;
                }
            };
            let box key = PBC::key_from_file(key_file.as_slice());

            let pbc = PBC::new(&key, &[0u8, ..16]);
            if matches.opt_present("d") {
                pbc.dec_file(&mut file_in, &mut file_out);
            } else {
                pbc.enc_file(&mut file_in, &mut file_out);
            }
        },
        "hash" if free_len == 2 => {
            let path_in = Path::new(matches.free.get(1).as_slice());
            let mut file_in = File::open(&path_in).unwrap();
            let box h = h_file(&mut file_in);
            print_array(&h);
        },
        "ds" if free_len == 2 => {
            let path_in_str = matches.free.get(1);
            let path_in = Path::new(path_in_str.as_slice());
            let mut file_in = File::open(&path_in).unwrap();

            let key_file = match matches.opt_str("k") {
                Some(k) => k,
                None if !matches.opt_present("v")  => {
                    let mut private_key_path = path_in_str.clone();
                    private_key_path.push_str(".dspk");
                    DigSig::rnd_key(private_key_path.as_slice());
                    private_key_path
                },
                _ => {
                    print_usage(program.as_slice(), &opts);
                    return;
                }
            };
            let key = DigSig::key_from_file(key_file.as_slice());

            if matches.opt_present("v") {
                let ds_path = matches.opt_str("v").unwrap();
                let ds = DigSig::from_file(ds_path.as_slice());
                match ds.verify_file(&mut file_in, key) {
                    true => println!("Correct!"),
                    false => println!("Incorrect!"),
                };
            } else {
                let (y, ds) = DigSig::of_file(&mut file_in, &key);
                let mut ds_path = path_in_str.clone();
                let mut y_path = path_in_str.clone();
                ds_path.push_str(".ds");
                y_path.push_str(".dsok");
                ds.to_file(ds_path.as_slice());
                DigSig::key_to_file(y_path.as_slice(), &y);
            }
        },
        _ => {
            print_usage(program.as_slice(), &opts);
            return;
        }
    }
}


#[cfg(test)]
mod tests {
    extern crate num;

    use std::num::{One, Zero};
    use num::bigint::{BigUint, ToBigUint};
    use std::num::from_uint;
    use super::pow_bigint;

    fn pow_bigint_args_u(num: uint, n: uint, res: uint)
                         -> (BigUint, BigUint, BigUint) {
        (num.to_biguint().unwrap(), n.to_biguint().unwrap(),
         res.to_biguint().unwrap())
    }

    fn pow_bigint_args_s(num: &str, n: &str, res: &str) -> (BigUint, BigUint, BigUint) {
        (from_str(num).unwrap(), from_str(n).unwrap(), from_str(res).unwrap())
    }
    
    #[test]
    fn test_pow_bigint_with_uint() {
        let (num1, n1, res1) = pow_bigint_args_u(8, 1, 8);
        let (num2, n2, res2) = pow_bigint_args_u(5, 0, 1);
        let (num3, n3, res3) = pow_bigint_args_u(2, 2, 4);
        let (num4, n4, res4) = pow_bigint_args_u(10, 5, 100000);

        assert_eq!(pow_bigint(num1, n1), res1);
        assert_eq!(pow_bigint(num2, n2), res2);
        assert_eq!(pow_bigint(num3, n3), res3);
        assert_eq!(pow_bigint(num4, n4), res4);
    }
}
