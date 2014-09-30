#![warn(unused_must_use)]
use std::io::{File, IoResult, EndOfFile};
use utils::{B16, fill_with_end_bits, is_file_size_can_fit
            , fill_with_file_size, xor_array_16, file_size, get_original_size};
use std::rand::random;
use magenta::Magenta;


pub struct PBC {
    k: B16,
    p0: B16
}


impl PBC {
    pub fn new(k: &B16, p0: &B16) -> PBC {
        PBC { k: *k.clone(), p0: *p0.clone() }
    }

    pub fn key_from_file(file_path: &str) -> Box<B16> {
        let mut file = File::open(&Path::new(file_path)).unwrap();
        let mut key: B16 = [0, ..16];
        file.read(key);
        box key
    }

    pub fn rnd_key(file_path: &str) {
        let mut key: B16 = [0, ..16];
        for i in range(0, 16) {
            key[i] = random();
        }

        let mut file = File::create(&Path::new(file_path)).unwrap();
        file.write(key);
    }

    pub fn enc_file(&self, file_in: &mut File, file_out: &mut File) -> IoResult<u64> {
        let buf_len = 16;
        let mut ci: B16;
        let mut buf_prev: B16 = self.p0;
        let mut buf_cur: B16;
        let mut is_filled = false;
        let mut byte_count: uint;
        let mut byte_total: u64 = 0;

        loop {
            buf_cur = [0, ..16];
            match file_in.read(buf_cur) {
                Err(e) => {
                    if e.kind == EndOfFile && is_filled {
                        break;
                    } else if is_filled {
                        fail!("pbc: {}", e.desc);
                    } else {
                        byte_count = 0;
                    }
                },
                Ok(i) => { byte_count = i; },
            };

            if byte_count < buf_len {
                fill_with_end_bits(buf_cur.slice_from_mut(byte_count));

                if !is_file_size_can_fit(byte_count, buf_len) {
                    ci = *self.enc_func(&buf_cur, &buf_prev);
                    try!(file_out.write(&ci));
                    byte_total += buf_len as u64;
                    buf_prev = buf_cur;

                    buf_cur = [0, ..16];
                }
                fill_with_file_size(file_in, buf_cur);
                is_filled = true;
            }

            ci = *self.enc_func(&buf_cur, &buf_prev);
            try!(file_out.write(&ci));
            byte_total += buf_len as u64;
            buf_prev = buf_cur;
        }
        Ok(byte_total)
    }

    pub fn dec_file(&self, file_in: &mut File, file_out: &mut File) {
        let buf_len = 16;
        let mut p_cur: B16;
        let mut p_prev: B16 = self.p0;
        let mut c_cur: B16;
        let fs = file_size(file_in);
        let block_count = fs / buf_len;

        for i in range(0, block_count - 2) {
            c_cur = [0, ..16];
            file_in.read(c_cur);
            p_cur = *self.dec_func(&p_prev, &c_cur);
            file_out.write(&p_cur);
            p_prev = p_cur;
        }

        c_cur = [0, ..16];
        file_in.read(c_cur);
        let first_block: B16 = *self.dec_func(&p_prev, &c_cur);
        c_cur = [0, ..16];
        file_in.read(c_cur);
        let second_block: B16 = *self.dec_func(&first_block, &c_cur);

        let original_size = get_original_size(&second_block);
        let remain_size = original_size - (block_count - 2) * buf_len;
        let block_remain = (remain_size - buf_len) as uint;
        if remain_size >= buf_len {
            file_out.write(&first_block);
            file_out.write(second_block.slice_to(block_remain));
        } else {
            file_out.write(first_block.slice_to(block_remain));
        }
    }

    fn enc_func(&self, buf_cur: &B16, buf_prev: &B16) -> Box<B16> {
        let box ek = Magenta::new_128(&self.k).enc(buf_cur);
        xor_array_16(&ek, buf_prev)
    }

    fn dec_func(&self, buf_prev: &B16, ci: &B16) -> Box<B16> {
        let box m = xor_array_16(buf_prev, ci);
        Magenta::new_128(&self.k).dec(&m)
    }
}
