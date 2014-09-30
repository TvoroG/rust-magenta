use std::io::File;
use std::rand;
use num::bigint::{BigUint, ToBigUint, RandBigInt};
use std::num::One;
use hash::h_file;
use utils::mod_pow;
use std::num::ToStrRadix;
use std::num::from_str_radix;


pub struct DigSig {
    r: BigUint,
    s: BigUint
}


impl DigSig {
    pub fn from_file(ds_path: &str) -> DigSig {
        let mut file = File::open(&Path::new(ds_path)).unwrap();
        let s = file.read_to_string().unwrap();

        let ls: Vec<&str> = s.as_slice().lines().collect();
        if ls.len() != 2 {
            fail!("incorrect digital signature file");
        }
        
        DigSig {
            r: from_str(ls[0]).unwrap(),
            s: from_str(ls[1]).unwrap() 
        }
    }

    pub fn of_file(file: &mut File, x: &BigUint) -> (BigUint, DigSig) {
        let (p, q) = DigSig::get_p_and_q();
        let k = DigSig::random_k(1, &q);
        let h = DigSig::calc_h(file);
        let g = DigSig::calc_g(&p, &q);
        let y = DigSig::calc_y(&p, &g, x);
        let r = DigSig::calc_r(&p, &k, &g);
        let s = DigSig::calc_s(&q, &k, &h, &r, x);
        (y, DigSig{r: r, s: s})
    }

    pub fn verify_file(self, file: &mut File, y: BigUint) -> bool {
        let (p, q) = DigSig::get_p_and_q();
        let g = DigSig::calc_g(&p, &q);
        let h = DigSig::calc_h(file);
        let rho = DigSig::calc_rho(&self.r, &q);

        mod_pow(self.r, h, p.clone()) == mod_pow(g, self.s, p.clone()) *
            mod_pow(y.clone(), rho, p.clone()) % p
    }

    pub fn to_file(&self, file_path: &str) {
        let mut file = File::create(&Path::new(file_path)).unwrap();
        let r_str = self.r.to_str_radix(10);
        let s_str = self.s.to_str_radix(10);
        file.write_str(r_str.as_slice());
        file.write_char('\n');
        file.write_str(s_str.as_slice());
    }

    pub fn key_to_file(file_path: &str, k: &BigUint) {
        let mut file = File::create(&Path::new(file_path)).unwrap();
        let k_str = k.to_str_radix(10);
        file.write_str(k_str.as_slice());
    }

    pub fn key_from_file(file_path: &str) -> BigUint {
        let mut file = File::open(&Path::new(file_path)).unwrap();
        let content = file.read_to_string().unwrap();
        from_str_radix(content.as_slice(), 10).unwrap()
    }

    pub fn rnd_key(file_path: &str) {
        let (_, q) = DigSig::get_p_and_q();
        let key = DigSig::random_k(2, &q);
        DigSig::key_to_file(file_path, &key);
    }

    fn get_p_and_q() -> (BigUint, BigUint) {
        let p: BigUint = from_str("13232376895198612407547930718267435757728527029623408872245156039757713029036368719146452186041204237350521785240337048752071462798273003935646236777459223").unwrap();
        let q: BigUint = from_str("857393771208094202104259627990318636601332086981").unwrap();
        (p, q)
    }

    fn random_k(from: uint, q: &BigUint) -> BigUint {
        let mut rng = rand::task_rng();
        let low = from.to_biguint().unwrap();
        let high = q - low;
        rng.gen_biguint_range(&low, &high)
    }

    fn calc_h(file: &mut File) -> BigUint {
        let box h_array = h_file(file);
        let h_vec: Vec<u32> = h_array.iter().map(|&x| x as u32).collect();
        BigUint::new(h_vec)
    }

    fn calc_s(q: &BigUint, k: &BigUint, h: &BigUint,
              r: &BigUint, x: &BigUint) -> BigUint {
        let one: BigUint = One::one();
        let rho: BigUint = DigSig::calc_rho(r, q);
        ((*h) * (*k) - rho * (*x)) % *q
    }

    fn calc_rho(r: &BigUint, q: &BigUint) -> BigUint {
        *r % *q
    }

    fn calc_y(p: &BigUint, g: &BigUint, x: &BigUint) -> BigUint {
        mod_pow(g.clone(), x.clone(), p.clone())
    }

    fn calc_r(p: &BigUint, k: &BigUint, g: &BigUint) -> BigUint {
        mod_pow(g.clone(), k.clone(), p.clone())
    }

    fn calc_g(p: &BigUint, q: &BigUint) -> BigUint {
        let gamma: BigUint = from_str("7521483903782060346617399017671409232618347905458279916384743575270644052774952605706862089884256074095039537064180858502511421752637985122233359298954651").unwrap();
        let one: BigUint = One::one();
        mod_pow(gamma, (p - one) / q.clone(), p.clone())
    }
}
