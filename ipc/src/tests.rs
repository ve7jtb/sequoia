//! Test data for Sequoia.
//!
//! This module includes the test data from `ipc/tests/data` in a
//! structured way.

use std::collections::BTreeMap;

/// Returns the content of the given file below `ipc/tests/data`.
pub fn file(name: &str) -> &'static [u8] {
    use std::sync::OnceLock;

    static FILES: OnceLock<BTreeMap<&'static str, &'static [u8]>>
        = OnceLock::new();
    FILES.get_or_init(|| {
        let mut m: BTreeMap<&'static str, &'static [u8]> =
            Default::default();

        macro_rules! add {
            ( $key: expr, $path: expr ) => {
                m.insert($key, include_bytes!($path))
            }
        }
        include!(concat!(env!("OUT_DIR"), "/tests.index.rs.inc"));

        // Sanity checks.
        assert!(m.contains_key("sexp/rsa-signature.sexp"));
        m
    }).get(name).unwrap_or_else(|| panic!("No such file {:?}", name))
}

/// Returns the content of the given file below `ipc/tests/data/keys`.
#[allow(dead_code)]
pub fn key(name: &str) -> &'static [u8] {
    file(&format!("keys/{}", name))
}

/// Returns the content of the given file below `ipc/tests/data/keyboxes`.
pub fn keybox(name: &str) -> &'static [u8] {
    file(&format!("keyboxes/{}", name))
}

/// Returns the content of the given file below `ipc/tests/data/messages`.
#[allow(dead_code)]
pub fn message(name: &str) -> &'static [u8] {
    file(&format!("messages/{}", name))
}

struct NoopHandler;

impl crate::Handler for NoopHandler {
    fn handle(
        &self,
        network: capnp_rpc::twoparty::VatNetwork<
            tokio_util::compat::Compat<tokio::net::tcp::OwnedReadHalf>,
        >,
    ) -> capnp_rpc::RpcSystem<capnp_rpc::rpc_twoparty_capnp::Side> {
        capnp_rpc::RpcSystem::new(Box::new(network), None)
    }
}

#[test]
fn connect_missing_executable() -> crate::Result<()> {
    let ctx = crate::Context::configure()
        .ephemeral()
        .build()?;
    let desc = crate::Descriptor::new(
        &ctx,
        ctx.home().join("test.cookie"),
        ctx.home().join("missing-ipc-server"),
        |_desc, _local| Ok(Box::new(NoopHandler)),
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()?;

    let err = match rt.block_on(async {
        desc.connect_with_policy(crate::IPCPolicy::External)
    }) {
        Ok(_) => panic!("expected missing external server to fail"),
        Err(err) => err,
    };
    let io_err = err.downcast_ref::<std::io::Error>()
        .expect("expected std::io::Error");
    assert_eq!(io_err.kind(), std::io::ErrorKind::NotFound);

    rt.block_on(async {
        desc.connect_with_policy(crate::IPCPolicy::Robust).map(drop)
    })?;

    Ok(())
}
