use std::io::{File, EndOfFile};
use utils::{B16, fill_with_end_bits, is_file_size_can_fit, fill_with_file_size
            , xor_array_16};
use magenta::Magenta;


pub fn h_file(file: &mut File) -> Box<B16> {
    let buf_len = 16;
    let h0: Box<B16> = box [0, ..16];
    let mut h = h0;
    let mut buf: B16;
    let mut is_filled = false;
    let mut byte_count: uint;

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

        if byte_count < buf_len {
            fill_with_end_bits(buf.slice_from_mut(byte_count));

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
    let box e = Magenta::new_128(a).enc(&b);
    let c = &b;
    xor_array_16(&e, c)
}
