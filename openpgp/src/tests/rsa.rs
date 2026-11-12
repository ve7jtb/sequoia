use std::marker::PhantomData;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::{
    Result,
    packet::key::{self, Key4, SecretParts},
};

struct RsaKey {
    d: &'static [u8],
    p: &'static [u8],
    q: &'static [u8],
}

struct Pool {
    bits: usize,
    keys: &'static [RsaKey],
    next: AtomicUsize,
}

impl Pool {
    const fn new(bits: usize, keys: &'static [RsaKey]) -> Self {
        Self {
            bits,
            keys,
            next: AtomicUsize::new(0),
        }
    }

    fn take(&self) -> &'static RsaKey {
        let index = self.next.fetch_add(1, Ordering::Relaxed);
        self.keys.get(index).unwrap_or_else(|| {
            panic!("RSA test key pool for {} bits exhausted; rerun \
                    openpgp/examples/generate-rsa-test-keys.rs with a \
                    larger key count", self.bits)
        })
    }
}

include!("../../tests/data/keys/rsa.rs.inc");

// Keep the override thread-local so parallel tests do not affect each other.
std::thread_local! {
    static REAL_GENERATION: AtomicUsize = const { AtomicUsize::new(0) };
}

/// Imports the next unused test key, unless real generation is enabled.
pub fn get<R>(bits: usize) -> Option<Result<Key4<SecretParts, R>>>
    where R: key::KeyRole,
{
    if REAL_GENERATION.with(|count| count.load(Ordering::Relaxed)) != 0 {
        return None;
    }
    let pool = POOLS.iter().find(|pool| pool.bits == bits)
        .unwrap_or_else(|| {
            panic!("No RSA test key pool for {} bits; add this size to \
                    openpgp/examples/generate-rsa-test-keys.rs", bits)
        });
    let key = pool.take();
    Some(Key4::import_secret_rsa(key.d, key.p, key.q, None))
}

// The marker makes this !Send and !Sync: the guard count must be
// decremented on the thread that created the guard.
#[must_use]
pub struct RealGeneration(PhantomData<*const ()>);

/// Enables real RSA generation while any guard is active.
pub fn real_generation() -> RealGeneration {
    REAL_GENERATION.with(|count| count.fetch_add(1, Ordering::Relaxed));
    RealGeneration(PhantomData)
}

impl Drop for RealGeneration {
    fn drop(&mut self) {
        REAL_GENERATION.with(|count| count.fetch_sub(1, Ordering::Relaxed));
    }
}

mod tests {
    use super::*;
    use crate::packet::key::UnspecifiedRole;

    #[test]
    fn key_sizes() {
        for pool in &POOLS {
            let key: Key4<SecretParts, UnspecifiedRole>
                = Key4::generate_rsa(pool.bits).unwrap();
            assert_eq!(key.mpis().bits(), Some(pool.bits));
        }
    }

    #[test]
    fn distinct_keys() {
        let pool = Pool::new(POOLS[0].bits, &POOLS[0].keys[..2]);
        let first = pool.take();
        let second = pool.take();
        assert_ne!(first.p, second.p);
        assert_ne!(first.q, second.q);
        assert_ne!(first.d, second.d);
    }

    #[test]
    #[should_panic(expected = "exhausted")]
    fn exhaustion_does_not_wrap() {
        let pool = Pool::new(POOLS[0].bits, &POOLS[0].keys[..1]);
        pool.take();
        pool.take();
    }

    #[test]
    fn real_generation_scope() {
        assert!(get::<UnspecifiedRole>(2048).is_some());
        {
            let _guard = real_generation();
            assert!(get::<UnspecifiedRole>(2048).is_none());
            {
                let _nested = real_generation();
                assert!(get::<UnspecifiedRole>(2048).is_none());
            }
            assert!(get::<UnspecifiedRole>(2048).is_none());
        }
        assert!(get::<UnspecifiedRole>(2048).is_some());
    }

    #[test]
    fn real_generation_drop_order() {
        let outer = real_generation();
        let inner = real_generation();
        drop(outer);
        assert!(get::<UnspecifiedRole>(2048).is_none());
        drop(inner);
        assert!(get::<UnspecifiedRole>(2048).is_some());
    }
}
