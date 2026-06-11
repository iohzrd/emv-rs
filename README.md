# emv-rs

A pure-Rust [EMV 4.4 (2022)](https://www.emvco.com/specifications/) kernel.

## Running a transaction

`emv-test-transaction` walks a real ICC through every Book 3 §10 phase against
an attached PC/SC reader. It auto-discovers the four config files shipped in
the repository root ([`terminal.toml`](terminal.toml), [`aids.toml`](aids.toml),
[`capk.toml`](capk.toml), [`crl.toml`](crl.toml)) unless overridden.

```sh
cargo run --bin emv-test-transaction
```

A real online host is out of scope, so the CLI ships an `InteractiveHost` that
prompts on stdin for an issuer authorisation response. The prompt accepts a
hex BER-TLV blob containing tags `8A` (ARC), `91` (Issuer Authentication Data),
`71` / `72` (issuer scripts), or a 2-character ASCII ARC shortcut (`"00"` ⇒
approved, `"05"` ⇒ declined, `"Z1"` ⇒ terminal-set offline-decline, etc).

### Useful flags

| Flag                | Effect                                                         |
| ------------------- | -------------------------------------------------------------- |
| `--aid <HEX>`       | SELECT this AID directly instead of running PSE / List-of-AIDs |
| `--terminal <path>` | Override `terminal.toml` location                              |
| `--aids <path>`     | Override `aids.toml` location                                  |
| `--capk <path>`     | Override `capk.toml` location                                  |
| `--crl <path>`      | Override `crl.toml` location                                   |

`$EMV_CONFIG_DIR` is also honoured if no explicit `--*` flag is given.

## Contactless kernels

The contactless surface is (will be) per-kernel feature-gated so consumers pull only what
they need. Books A and B (cross-cutting types + Entry Point) are always on once
the `contactless` module is touched; individual kernels are opt-in:

| Feature    | Kernel                 | Status              |
| ---------- | ---------------------- | ------------------- |
| `kernel-2` | C-2 MasterCard PayPass | not yet implemented |
| `kernel-3` | C-3 Visa qVSDC         | not yet implemented |
| `kernel-4` | C-4 Amex ExpressPay    | not yet implemented |
| `kernel-5` | C-5 JCB J/Speedy       | not yet implemented |
| `kernel-6` | C-6 Discover D-PAS     | not yet implemented |
| `kernel-7` | C-7 UnionPay quickPass | not yet implemented |
| `kernel-8` | C-8 next-gen ECC       | not yet implemented |

Out of scope: Kernel 1 (Visa MSD v2.6, dropped from Book A v2.11) and Book D
(L1 RF / 14443-3 / T=CL - emv-rs assumes a working 14443-4 channel from the
host platform).

## Building

```sh
cargo build                                # default features (incl. pcsc)
cargo build --no-default-features          # library-only, no PC/SC system dep
cargo test  --no-default-features          # the contact kernel test suite
```

The `pcsc` feature pulls in `libpcsclite`; turn it off when building on a host
without the system library or for CI smoke-checks of the kernel itself.

## Status & conformance

emv-rs is **not an EMVCo type-approved kernel**. Production payment acceptance
requires EMV Level 2 type approval under the payment networks' rules; emv-rs is
intended for development, research, testing, and tooling.

Division of responsibility at the online boundary: issuer Authorisation
Response Code semantics are acquirer-domain (Book 4 Annex A6 defines only the
disposition categories), so the host classifies the issuer response and passes
an `OnlineAuthorisationOutcome` to `submit_authorisation_response`; the kernel
stores the ARC verbatim and never interprets it.

## License

Licensed under either of [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE), at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.

EMV® is a registered trademark of [EMVCo, LLC](https://www.emvco.com/). This
project is not affiliated with or endorsed by EMVCo.
