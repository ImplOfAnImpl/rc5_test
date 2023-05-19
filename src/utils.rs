//! Various utilities

use std::mem::size_of;

pub trait TypeSizeAssertHelper<T> {
    const EQ_GUARD: ();
}

impl<T1, T2> TypeSizeAssertHelper<T1> for T2 {
    const EQ_GUARD: () = {
        if size_of::<T1>() != size_of::<T2>() {
            panic!("type sizes are different");
        }
    };
}

// Note: as mentioned below, this static_assert can only fail during `cargo build`, but not during `cargo check`
// or a "no_run" doc test. So, don't use "no_run" in the tests below, because such a test can succeed even if it's
// incorrect (note that the "compile_fail" test does work correctly).

/// Fail the compilation if the passed types have different sizes.
/// 
/// E.g. this will fail:
/// ```compile_fail
/// # use rc5_test::utils::static_assert_size_eq;
/// # fn main() {
/// static_assert_size_eq!(u32, [u8; 3]);
/// # }
/// ```
/// and this will succeed:
/// ```
/// # use rc5_test::utils::static_assert_size_eq;
/// # fn main() {
/// static_assert_size_eq!(u32, [u8; 4]);
/// # }
/// ```
/// # Note
/// Due to some Rust's internal voodoo, such compilation test can only fail during `cargo build`, but not during
/// `cargo check` (so rust-analyzer won't complain about it either).
#[macro_export]
macro_rules! static_assert_size_eq {
    ($t1:ty, $t2: ty) => {
        {let _ = <$t1 as $crate::utils::TypeSizeAssertHelper<$t2>>::EQ_GUARD;}
    };
}

pub use static_assert_size_eq;
