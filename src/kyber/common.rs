use num_bigint::BigInt;

use super::constants::{KYBER_Q, QINV};

pub fn montgomery_reduce(a: &BigInt) -> BigInt {
    let t = a * QINV;
    (a - t * KYBER_Q) >> 16
}

pub fn barret_reduce(a: &BigInt) -> BigInt {
    let v = ((1 << 26) + KYBER_Q / 2) / KYBER_Q;
    let t = (v * a + (1 << 25)) >> 26;
    t * KYBER_Q
}
#[inline(always)]
pub fn fqmul(a: &BigInt, b: &BigInt) -> BigInt {
    montgomery_reduce(&(a * b))
}