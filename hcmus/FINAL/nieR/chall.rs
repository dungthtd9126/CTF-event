use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::env;
use std::fs;
use std::io::{BufWriter, Write};

const PBITS: u64 = 137;
const NDAT: usize = 137;
const C: u64 = 1337;
const DET_SEED: u64 = 0x9E37_79B9_7F4A_7C15;

fn read_flag_bytes() -> Vec<u8> {
    for p in ["flag.txt", "../flag.txt"] {
        if let Ok(b) = fs::read(p) {
            return b;
        }
    }
    std::process::exit(1);
}

#[inline]
fn lcg(s: &BigUint, n: &BigUint) -> BigUint {
    (BigUint::from(3u32) * s + BigUint::from(C)) % n
}

fn is_probable_prime<R: Rng>(n: &BigUint, rounds: u32, rng: &mut R) -> bool {
    let one = BigUint::one();
    let two = BigUint::from(2u32);
    let three = BigUint::from(3u32);
    if n < &two {
        return false;
    }
    if n == &two || n == &three {
        return true;
    }
    if !n.bit(0) {
        return false;
    }
    let n_minus_1 = n - &one;
    let mut d = n_minus_1.clone();
    let mut r = 0u32;
    while !d.bit(0) {
        d >>= 1;
        r += 1;
    }
    let n_minus_2 = n - &two;
    'witness: for _ in 0..rounds {
        let a = rng.gen_biguint_range(&two, &n_minus_2);
        let mut x = a.modpow(&d, n);
        if x == one || x == n_minus_1 {
            continue;
        }
        for _ in 0..r.saturating_sub(1) {
            x = x.modpow(&two, n);
            if x == n_minus_1 {
                continue 'witness;
            }
        }
        return false;
    }
    true
}

fn gen_prime<R: Rng>(bits: u64, rng: &mut R) -> BigUint {
    loop {
        let mut p = rng.gen_biguint(bits);
        p.set_bit(bits - 1, true);
        p.set_bit(0, true);
        if is_probable_prime(&p, 40, rng) {
            return p;
        }
    }
}

fn emit<W: Write>(
    out: &mut W,
    m: &BigUint,
    n: &BigUint,
    e0: BigUint,
    mut next_seed: impl FnMut(usize) -> BigUint,
) {
    writeln!(out, "N = {}", n).unwrap();
    let mut e = e0;
    for i in 0..NDAT {
        let e1 = lcg(&e, n);
        let e2 = lcg(&e1, n);
        let sum = m.modpow(&e1, n) + m.modpow(&e2, n);
        writeln!(out, "{}", sum).unwrap();
        e = next_seed(i);
        writeln!(out, "[DEBUG] e = {}", e).unwrap();
    }
}

fn extract_decimals(s: &str) -> Vec<BigUint> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for ch in s.chars() {
        if ch.is_ascii_digit() {
            cur.push(ch);
        } else if !cur.is_empty() {
            out.push(cur.parse::<BigUint>().unwrap());
            cur.clear();
        }
    }
    if !cur.is_empty() {
        out.push(cur.parse::<BigUint>().unwrap());
    }
    out
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let m = BigUint::from_bytes_be(&read_flag_bytes());
    let low = BigUint::from(731u32);

    let stdout = std::io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    if let Some(idx) = args.iter().position(|a| a == "--test-vector") {
        let path = args.get(idx + 1).expect("--test-vector <file>");
        let nums = extract_decimals(&fs::read_to_string(path).unwrap());
        assert_eq!(nums.len(), 3 + NDAT);
        let n = &nums[0] * &nums[1];
        let e0 = nums[2].clone();
        let seeds: Vec<BigUint> = nums[3..].to_vec();
        emit(&mut out, &m, &n, e0, |i| seeds[i].clone());
    } else if args.iter().any(|a| a == "--deterministic") {
        let mut rng = StdRng::seed_from_u64(DET_SEED);
        let n = &gen_prime(PBITS, &mut rng) * &gen_prime(PBITS, &mut rng);
        let e0 = rng.gen_biguint_range(&low, &n);
        emit(&mut out, &m, &n, e0, |_| rng.gen_biguint_range(&low, &n));
    } else {
        let mut rng = rand::thread_rng();
        let n = &gen_prime(PBITS, &mut rng) * &gen_prime(PBITS, &mut rng);
        let e0 = rng.gen_biguint_range(&low, &n);
        emit(&mut out, &m, &n, e0, |_| rng.gen_biguint_range(&low, &n));
    }

    out.flush().unwrap();
}
