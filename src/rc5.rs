//! RC5 cypher implementation

use crate::utils::static_assert_size_eq;
use bytemuck::{bytes_of, pod_read_unaligned};
use generic_array::{
    typenum::{U16, U4, U8},
    GenericArray,
};
use num::traits::{FromPrimitive, PrimInt, WrappingAdd, WrappingSub, Zero};
use std::cmp::max;
use std::mem::size_of;
use std::ops::Shl;
use zeroize::Zeroizing;

/// Generic implementation of the cypher.
///
/// Usage example:
///```
/// # use rc5_test::rc5::*;
/// // Any key length is OK.
/// let key = b"1234567890";
///
/// // Here we use the 32-bit flavor of the cypher (i.e. cypher's word length will be 32 bit).
/// // 12 is the number of rounds.
/// let cypher = Rc5Cypher::<Flavor32>::new(key, 12);
///
/// // The block length must be double the size of the cypher's word length.
/// let plain_text = b"12345678";
///
/// // Encryption will be performed in-place, so we need a mutable array.
/// let mut block = plain_text.clone();
///
/// cypher.encrypt_block((&mut block).into());
/// cypher.decrypt_block((&mut block).into());
/// # assert!(&block[..] == plain_text);
///```
pub struct Rc5Cypher<F: Flavor> {
    num_rounds: u8,
    expanded_key: Zeroizing<Vec<F::WordType>>,
}

impl<F: Flavor> Rc5Cypher<F> {
    pub fn new(key: &[u8], num_rounds: u8) -> Rc5Cypher<F> {
        Rc5Cypher { num_rounds, expanded_key: Rc5Cypher::<F>::expand_key(key, num_rounds) }
    }

    // Note: PrimInt::to_le below basically means "swap bytes if the platform is not le".

    pub fn encrypt_block(&self, block: &mut GenericArray<u8, F::BlockArraySizeTag>) {
        static_assert_size_eq!(GenericArray<u8, F::BlockArraySizeTag>, [F::WordType; 2]);

        let (block_1st_half, block_2nd_half) = block.split_at_mut(size_of::<F::WordType>());

        let mut a = pod_read_unaligned::<F::WordType>(block_1st_half).to_le();
        let mut b = pod_read_unaligned::<F::WordType>(block_2nd_half).to_le();

        a = a.wrapping_add(&self.expanded_key[0]);
        b = b.wrapping_add(&self.expanded_key[1]);

        for i in 1..=self.num_rounds as usize {
            a = (a ^ b).rotate_left(adjust_rot_amount(b)).wrapping_add(&self.expanded_key[2 * i]);
            b = (a ^ b).rotate_left(adjust_rot_amount(a)).wrapping_add(&self.expanded_key[2 * i + 1]);
        }

        block_1st_half.copy_from_slice(bytes_of(&a.to_le()));
        block_2nd_half.copy_from_slice(bytes_of(&b.to_le()));
    }

    pub fn decrypt_block(&self, block: &mut GenericArray<u8, F::BlockArraySizeTag>) {
        static_assert_size_eq!(GenericArray<u8, F::BlockArraySizeTag>, [F::WordType; 2]);

        let (block_1st_half, block_2nd_half) = block.split_at_mut(size_of::<F::WordType>());

        let mut a = pod_read_unaligned::<F::WordType>(block_1st_half).to_le();
        let mut b = pod_read_unaligned::<F::WordType>(block_2nd_half).to_le();

        for i in (1..=self.num_rounds as usize).rev() {
            b = (b.wrapping_sub(&self.expanded_key[2 * i + 1])).rotate_right(adjust_rot_amount(a)) ^ a;
            a = (a.wrapping_sub(&self.expanded_key[2 * i])).rotate_right(adjust_rot_amount(b)) ^ b;
        }

        b = b.wrapping_sub(&self.expanded_key[1]);
        a = a.wrapping_sub(&self.expanded_key[0]);

        block_1st_half.copy_from_slice(bytes_of(&a.to_le()));
        block_2nd_half.copy_from_slice(bytes_of(&b.to_le()));
    }

    fn expand_key(key: &[u8], num_rounds: u8) -> Zeroizing<Vec<F::WordType>> {
        // Note: here zeroize is used to make sure that the key won't be left in memory after the cypher object
        // is destroyed. However, zeroize won't help if a reallocation occurs due to a vector's capacity change,
        // so it's important to reserve the required capacities in advance.

        let word_size = size_of::<F::WordType>();
        let num_words_in_key = if key.len() == 0 { 1 } else { (key.len() + word_size - 1) / word_size };

        // This is called "L" in the spec.
        let key_as_words = {
            let mut result = Zeroizing::new(vec![F::WordType::zero(); num_words_in_key]);

            for byte_idx in (0..key.len()).rev() {
                let word_idx = byte_idx / word_size;
                // Note: this unwrap should never fail
                let cast_byte = F::WordType::from_u8(key[byte_idx]).unwrap();
                result[word_idx] = result[word_idx].shl(8).wrapping_add(&cast_byte);
            }

            result
        };

        let expanded_key_len = 2 * (num_rounds as usize + 1);
        // This is called "S" in the spec.
        let mut expanded_key: Zeroizing<Vec<F::WordType>> = Zeroizing::new(Vec::with_capacity(expanded_key_len));

        // Basic initialization
        expanded_key.push(F::MAGIC_P);
        for _ in 0..(expanded_key_len - 1) {
            // Note: can't combine these 2 lines into one, because apparently both of them borrow expanded_key
            // as mutable.
            let val = expanded_key.last().unwrap().wrapping_add(&F::MAGIC_Q);
            expanded_key.push(val);
        }

        // Mix in the key
        {
            let mut key_as_words = key_as_words;
            let mut i = 0;
            let mut j = 0;
            let mut a = F::WordType::zero();
            let mut b = F::WordType::zero();

            for _ in 0..(3 * max(expanded_key.len(), key_as_words.len())) {
                let ab = a.wrapping_add(&b);
                a = expanded_key[i].wrapping_add(&ab).rotate_left(3);
                expanded_key[i] = a;

                let ab = a.wrapping_add(&b);
                b = key_as_words[j].wrapping_add(&ab).rotate_left(adjust_rot_amount(ab));
                key_as_words[j] = b;

                i = (i + 1) % expanded_key.len();
                j = (j + 1) % key_as_words.len();
            }
        }

        expanded_key
    }
}

// Adjust the number of bits for calls to PrimInt::rotate_left or rotate_right, in case it's too large.
fn adjust_rot_amount<T: PrimInt + FromPrimitive>(num_bits: T) -> u32 {
    // Note: neither of these unwraps can fail (the number of bits in T will always fit into T and into u32)
    (num_bits % T::from_usize(size_of::<T>() * 8).unwrap()).to_u32().unwrap()
}

/// A sealed trait that all "flavor" structs implement.
pub trait Flavor: private::InternalFlavor {}

/// Selector for the 16-bit version of the cypher. The block size will be 32 bit.
pub struct Flavor16;

/// Selector for the 32-bit version of the cypher. The block size will be 64 bit.
pub struct Flavor32;

/// Selector for the 64-bit version of the cypher. The block size will be 128 bit.
pub struct Flavor64;

pub type Rc5Cypher16 = Rc5Cypher<Flavor16>;
pub type Rc5Cypher32 = Rc5Cypher<Flavor32>;
pub type Rc5Cypher64 = Rc5Cypher<Flavor64>;

macro_rules! define_flavor {
    ($name:ident, $word_type:ty, $block_size_tag:ty, $magic_p:expr, $magic_q:expr) => {
        impl private::InternalFlavor for $name {
            type WordType = $word_type;
            type BlockArraySizeTag = $block_size_tag;

            const MAGIC_P: Self::WordType = $magic_p;
            const MAGIC_Q: Self::WordType = $magic_q;
        }

        impl Flavor for $name {}
    };
}

define_flavor!(Flavor16, u16, U4, 0xb7e1, 0x9e37);
define_flavor!(Flavor32, u32, U8, 0xb7e15163, 0x9e3779b9);
define_flavor!(Flavor64, u64, U16, 0xb7e151628aed2a6b, 0x9e3779b97f4a7c15);

mod private {
    use bytemuck::Pod;
    use generic_array::ArrayLength;
    use num::traits::{FromPrimitive, PrimInt, ToPrimitive, Unsigned, WrappingAdd, WrappingSub, Zero};
    use zeroize::Zeroize;

    pub trait InternalFlavor {
        // Cypher's word type
        type WordType: PrimInt
            + Unsigned
            + WrappingAdd
            + WrappingSub
            + Zero
            + FromPrimitive
            + ToPrimitive
            + Pod
            + Zeroize;
        // Size tag type for the GenericArray that will be used as the in-out parameter of encrypt/decrypt_block.
        type BlockArraySizeTag: ArrayLength<u8>;

        // "Magic" constants that are defined in the spec.
        const MAGIC_P: Self::WordType;
        const MAGIC_Q: Self::WordType;
    }
}
