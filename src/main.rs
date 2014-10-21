/*
The MAGENTA Block Cipher (M. J. Jacobson, Jr. and K. Hubery) implementation.
http://edipermadi.files.wordpress.com/2008/09/magenta-spec.pdf
*/
extern crate getopts;
extern crate magenta;
extern crate num;

use std::io::{File, IoErrorKind, EndOfFile, IoResult, Truncate, ReadWrite
              , SeekEnd, SeekSet, BufferedReader};
use std::io::fs::{rmdir_recursive, copy};
use std::fmt::Show;
use std::os;
use std::default::Default;
use std::fmt::radix;
use getopts::{optopt,optflag,getopts,OptGroup,Matches};
use num::bigint::{BigUint, ToBigUint, RandBigInt};
use std::num::from_str_radix;
use magenta::pbc::PBC;
use magenta::ds::DigSig;
use magenta::hash::h_file;
use magenta::utils::{print_array};


fn print_usage(program: &str, opts: &[OptGroup]) {
    println!("Usage: {} encrypt [-p|--private_key path] [-s|--private_ds_key path] <input_file> <output_file>", program);
    println!("       {} decrypt <-p|--private_key path> <-o|--open_ds_key path> <input_file> <output_file>", program);
    println!("       {} pbc [-k|--key path] <input_file> <output_file>", program);
    println!("       {} pbc <-d|--dec> <-k|--key path> <input_file> <output_file>", program);
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
        optopt("s", "private_ds_key", "private ds key file", "hint"),
        optopt("o", "open_ds_key", "open ds key file", "hint"),
        optopt("p", "private_key", "private pbc key file", "hint"),
    ];

    let matches = match getopts(args.tail(), opts) {
        Ok(m) => { m }
        Err(f) => { fail!(f.to_string()) }
    };


    if matches.opt_present("h") {
        print_usage(program.as_slice(), &opts);
        return;
    }

    let command = match matches.free[0].as_slice() {
        c @ "pbc" | c @ "hash" | c @ "ds" | c @ "encrypt" | c @ "decrypt" => c,
        _ => {
            print_usage(program.as_slice(), &opts);
            return;
        }
    };

    let free_len = matches.free.len();
    match command {
        "encrypt" if free_len == 3 => {
            let path_in_str = &matches.free[1];
            let path_in = Path::new(path_in_str.as_slice());
            let path_out = Path::new(matches.free[2].as_slice());
            let path_temp = path_in.clone().with_extension("temp");

            {
                let mut temp_file =
                    File::open_mode(&path_temp, Truncate, ReadWrite).unwrap();
                let mut file_in = File::open(&path_in).unwrap();

                copy(&path_in, &path_temp);

                let (y, ds) = do_ds(&mut temp_file, &matches.opt_str("s"));
                save_ds_ok(&y, path_in_str);
                concat_ds(&ds, &mut temp_file);
            }
            
            let mut file_out = File::create(&path_out).unwrap();
            let mut temp_file = File::open(&path_temp).unwrap();
            do_pbc(&mut temp_file, &mut file_out, true, &matches.opt_str("p"));
        }
        "decrypt" if (free_len == 3
            && matches.opt_str("p").is_some()
            && matches.opt_str("o").is_some()) => {

            let path_in_str = &matches.free[1];
            let path_in = Path::new(path_in_str.as_slice());
            let path_out = Path::new(matches.free[2].as_slice());
            let path_temp = path_in.clone().with_extension("temp");

            {
                let mut file_in = File::open(&path_in).unwrap();
                let mut file_temp = File::create(&path_temp).unwrap();
                do_pbc(&mut file_in, &mut file_temp, false, &matches.opt_str("p"));
            }

            let (r, s) = read_ds(&path_temp, &path_out);
            let mut file_out = File::open(&path_out).unwrap();
            let key_path = &matches.opt_str("o").unwrap();

            match do_ds_verifying(&mut file_out, key_path, (&r, &s)) {
                true => println!("Correct!"),
                false => println!("Incorrect!"),
            }
        }
        "pbc" if free_len == 3 => {
            let path_in_str = &matches.free[1];
            let path_in = Path::new(path_in_str.as_slice());
            let path_out = Path::new(matches.free[2].as_slice());

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
            let path_in = Path::new(matches.free[1].as_slice());
            let mut file_in = File::open(&path_in).unwrap();
            let box h = h_file(&mut file_in);
            print_array(&h);
        },
        "ds" if free_len == 2 => {
            let path_in_str = &matches.free[1];
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


fn get_or_create_ds_pk(file_in: &File, key_path: &Option<String>) -> String {
    match *key_path {
        Some(ref k) => k.clone(),
        None => {
            let mut private_key_path
                = file_in.path().as_str().unwrap().into_string();
            private_key_path.push_str(".dspk");
            DigSig::rnd_key(private_key_path.as_slice());
            private_key_path
        },
    }    
}

fn get_or_create_pbc_pk(file_in: &File, key_path: &Option<String>) -> String {
    match *key_path {
        Some(ref k) => k.clone(),
        None => {
            let mut private_key_path =
                file_in.path().as_str().unwrap().into_string();
            private_key_path.push_str(".pk");
            PBC::rnd_key(private_key_path.as_slice());
            private_key_path
        },
    }
}


fn do_ds(file_in: &mut File, key_path: &Option<String>) -> (BigUint, DigSig) {
    let key_file = get_or_create_ds_pk(file_in, key_path);
    let key = DigSig::key_from_file(key_file.as_slice());
    DigSig::of_file(file_in, &key)
}


fn do_ds_verifying(file_in: &mut File, key_path: &String, sig: (&BigUint, &BigUint)) -> bool {
    let key = DigSig::key_from_file(key_path.as_slice());
    let (r, s) = sig;
    let ds = DigSig::new(r.clone(), s.clone());
    ds.verify_file(file_in, key)
}


fn do_pbc(file_in: &mut File, file_out: &mut File, is_enc: bool, key_path: &Option<String>) {
    let key_file = get_or_create_pbc_pk(file_in, key_path);
    let box key = PBC::key_from_file(key_file.as_slice());

    let pbc = PBC::new(&key, &[0u8, ..16]);
    if is_enc {
        pbc.enc_file(file_in, file_out);
    } else {
        pbc.dec_file(file_in, file_out);
    }
}


fn save_ds_ok(y: &BigUint, y_path_str: &String) {
    let mut y_path = y_path_str.clone();
    y_path.push_str(".dsok");
    DigSig::key_to_file(y_path.as_slice(), y);
}


fn concat_ds(ds: &DigSig, file_in: &mut File) {
    let r_str = format!("\n{}", ds.r);
    let s_str = format!("\n{}", ds.s);
    file_in.seek(0, SeekEnd);
    file_in.write(r_str.as_bytes());
    file_in.write(s_str.as_bytes());
}


fn read_ds(path_temp: &Path, path_out: &Path) -> (BigUint, BigUint) {
    fn str_init(s: &String) -> String {
        let mut l = s.clone();
        l.remove(s.len() - 1);
        l
    }

    let file_temp = File::open(path_temp).unwrap();
    let mut temp_reader = BufferedReader::new(file_temp);
    let mut file_out = File::create(path_out).unwrap();

    let lines: Vec<String> = temp_reader.lines().map(|l| l.unwrap()).collect();
    let line_count = lines.len();

    for (i, line) in lines.iter().take(line_count - 2).enumerate() {
        if line_count - 3 == i {
            file_out.write_str(str_init(line).as_slice());
        } else {
            file_out.write_str(line.as_slice());
        }        
    }

    let r_str = &lines[line_count - 2];
    let s_str = &lines[line_count - 1];

    let r = from_str(str_init(r_str).as_slice()).unwrap();
    let s = from_str(s_str.as_slice()).unwrap();

    (r, s)
}
