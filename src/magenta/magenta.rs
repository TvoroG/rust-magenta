
use utils::{B8, B16, B24, B32, concat_u8, nth_byte, part, xor_array
            , concat_arrays_u8};

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

pub enum Magenta {
    Key128(B16),
    Key192(B24),
    Key256(B32)
}


impl Magenta {
    pub fn new_128(k: &B16) -> Magenta {
        Key128(*k.clone())
    }

    pub fn new_192(k: &B24) -> Magenta {
        Key192(*k.clone())
    }

    pub fn new_256(k: &B32) -> Magenta {
        Key256(*k.clone())
    }

    pub fn enc(&self, m: &B16) -> Box<B16> {
        let mut res = box *m;
        let divided_key = self.divide_key();
        let key_parts_seq = self.key_parts_seq();

        for part_i in key_parts_seq.iter() {
            res = self.feistel_round(&*res, &divided_key[*part_i - 1]);
        }
        res
    }

    pub fn dec(&self, m: &B16) -> Box<B16> {
        let box enced = self.enc(&*self.v(m));
        self.v(&enced)
    }

    pub fn key(self) -> Vec<u8> {
        match self {
            Key128(k) => Vec::from_slice(k.as_slice()),
            Key192(k) => Vec::from_slice(k.as_slice()),
            Key256(k) => Vec::from_slice(k.as_slice()),
        }
    }

    fn feistel_round(&self, x: &B16, y: &B8) -> Box<B16> {
        let box x1 = part(0, x);
        let box x2 = part(1, x);
        let r = 3u;
        let box e_array = concat_arrays_u8(&x2, y);

        concat_arrays_u8(&x2, &*xor_array(&x1, &*self.e(r, &e_array)))
    }

    fn key_parts_count(self) -> uint {
        match self {
            Key128(..) => 2,
            Key192(..) => 3,
            Key256(..) => 4,
        }
    }

    fn key_parts_seq(self) -> Vec<uint> {
        match self {
            Key128(..) => vec![1u, 1, 2, 2, 1, 1],
            Key192(..) => vec![1u, 2, 3, 3, 2, 1],
            Key256(..) => vec![1u, 2, 3, 4, 4, 3, 2, 1],
        }
    }

    fn divide_key(&self) -> Vec<B8> {
        let mut divided_key = Vec::new();
        let k_parts_count: uint = self.key_parts_count();
        let key = self.key();

        for i in range(0, k_parts_count) {
            divided_key.push(*part(i, key.as_slice()));
        }
        divided_key
    }

    fn xe(&self, x: &B16) -> Box<B8> {
        let mut v = box [0, ..8];

        for i in range(0, 8) {
            v[i] = x[i * 2];
        }
        v
    }

    fn xo(&self, x: &B16) -> Box<B8> {
        let mut v = box [0, ..8];

        for i in range(0, 8) {
            v[i] = x[i * 2 + 1];
        }
        v
    }

    fn f(&self, x: u8) -> u8 {
        s_block[x as uint]
    }

    fn a(&self, x: u8, y: u8) -> u8 {
        self.f(x ^ self.f(y))
    }

    fn pe(&self, x: u8, y: u8) -> u16 {
        concat_u8(self.a(x, y), self.a(y, x))
    }

    fn p(&self, x: &B16) -> Box<B16> {
        let mut v = box [0, ..16];
        let mut pe_x: u16;
        let mut x1: u8;
        let mut x2: u8;

        for i in range(0, 8) {
            x1 = x[i];
            x2 = x[i + 8];
            pe_x = self.pe(x1, x2);
            v[i * 2] = nth_byte(pe_x as uint, 1);
            v[i * 2 + 1] = nth_byte(pe_x as uint, 0);
        }
        v
    }

    fn t(&self, x: &B16) -> Box<B16> {
        self.p(&*self.p(&*self.p(&*self.p(x))))
    }

    fn c(&self, r: uint, x: &B16) -> Box<B16> {
        if r == 1 {
            self.t(x)
        } else {
            let box c_prev = self.c(r - 1, x);
            let box c_e = self.xe(&c_prev);
            let box c_o = self.xo(&c_prev);

            let box xor1 = xor_array(&c_e, &*part(0, x));
            let box xor2 = xor_array(&c_o, &*part(1, x));
            let box x_next = concat_arrays_u8(&xor1, &xor2);
            self.t(&x_next)
        }
    }

    fn e(&self, r: uint, x: &B16) -> Box<B8>{
        self.xe(&*self.c(r, x))
    }

    fn v(&self, x: &B16) -> Box<B16> {
        let mut vv = box [0, ..16];

        for i in range(0, 8) {
            vv[i] = x[i + 8];
            vv[i + 8] = x[i];
        }
        vv
    }
}
