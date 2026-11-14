// chirp-auth-server's own src/main.rs, word for word: the binary is the
// library's entrypoint, so this one is the same issuer.

fn main() -> anyhow::Result<()> {
    chirp_service::run()
}
