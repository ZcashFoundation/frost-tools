# Zcash Foundation FROST Demos

This repository contains a set of command line demos that uses the [ZF
FROST](https://frost.zfnd.org/) libraries and reference implementation. Their
purpose is to:

1. identify gaps in our documentation
2. provide usage examples for developer facing documentation
3. provide reference implementations for developers wanting to use FROST in a “real world” scenario.

The demos use the [Ed25519](https://crates.io/crates/frost-ed25519) ciphersuite
by default, but they can also use the
[RedPallas](https://github.com/ZcashFoundation/reddsa/) ciphersuite which is
compatible with Zcash, and the [Secp256k1-TR](https://crates.io/crates/frost-secp256k1-tr) ciphersuite
which is compatible with Bitcoin taproot.

## About FROST (Flexible Round-Optimised Schnorr Threshold signatures)

Unlike signatures in a single-party setting, threshold signatures require cooperation among a threshold number of signers, each holding a share of a common private key. The security of threshold
schemes in general assume that an adversary can corrupt strictly fewer than a threshold number of participants.

[Two-Round Threshold Schnorr Signatures with FROST](https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/) presents a variant of a Flexible Round-Optimized Schnorr Threshold (FROST) signature scheme originally defined in [FROST20](https://eprint.iacr.org/2020/852.pdf). FROST reduces network overhead during threshold
signing operations while employing a novel technique to protect against forgery attacks applicable to prior Schnorr-based threshold signature constructions. This variant of FROST requires two rounds to compute a signature, and implements signing efficiency improvements described by [Schnorr21](https://eprint.iacr.org/2021/1375.pdf). Single-round signing with FROST is not implemented here.

## Projects

This repo contains 4 projects:

1. [Trusted Dealer](https://github.com/ZcashFoundation/frost-zcash-demo/tree/main/trusted-dealer)
2. [DKG](https://github.com/ZcashFoundation/frost-zcash-demo/tree/main/dkg)
3. [Coordinator](https://github.com/ZcashFoundation/frost-zcash-demo/tree/main/coordinator)
4. [Participant](https://github.com/ZcashFoundation/frost-zcash-demo/tree/main/participant)
5. [Server](https://github.com/ZcashFoundation/frost-zcash-demo/tree/main/server)
6. [FROST client](https://github.com/ZcashFoundation/frost-zcash-demo/tree/main/frost-client)
7. [Zcash Signer](https://github.com/ZcashFoundation/frost-zcash-demo/tree/main/zcash-sign)

The first four are command line tools that generate FROST shares and run the
FROST protocol. They offer multiple communication interfaces, from copy & pasting
to using the Server; see below.

The Server helps participants and coordinators communicate with each other.

The FROST client is a CLI tool that serves as an example of how to interact
with the server.

The Zcash Signer is a standalone tool that allows signing a Zcash transaction
with an externally-generated signature (e.g. using FROST, but could be something
else).


## Status ⚠

Trusted Dealer demo - WIP
DKG demo - WIP
Coordinator demo - WIP
Participant demo - WIP

## Usage

NOTE: This is for demo purposes only and should not be used in production.

You will need to have [Rust and Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) installed.

To run:
1. Clone the repo. Run `git clone https://github.com/ZcashFoundation/frost-zcash-demo.git`
2. Run:

```bash
# installs: frost-client, coordinator, dkg, participant, trusted-dealer
cargo install --path frost-client

# installs: frostd
cargo install --path frostd

# installs: zcash-sign
# NOTE: Currently fails to build.
cargo install --path zcash-sign
```

If running from installed binaries, in separate terminals:

1. Run `trusted-dealer` or `dkg`
2. Run `coordinator`
3. Run `participant`. Do this in separate terminals for separate participants.

If running from source, in separate terminals:
1. Run `cargo run --bin trusted-dealer` or `cargo run --bin dkg`
2. Run `cargo run --bin coordinator`
3. Run `cargo run --bin participants`. Do this in separate terminals for separate participants.

The demos support three communication mechanisms. By using the `--cli` flag (e.g.
`cargo run --bin dkg -- --cli`), they will print JSON objects to the terminal,
and participants will need to copy & paste objects and send them amongst
themselves to complete the protocol.

Without the `--cli` flag, the demos will use socket communications. The
coordinator will act as the server and the participants will be clients. With
the `--http` flag, the demos will use socket communications, using a server (in
the `server` crate) to coordinate communications. See examples below.

## Socket communication example

Create 3 key shares with threshold 2 using trusted dealer:

```
cargo run --bin trusted-dealer -- -t 2 -n 3
```

To use a different ciphersuite, add the `-C` flag:

```
# For RedPallas (Zcash compatible)
cargo run --bin trusted-dealer -- -t 2 -n 3 -C redpallas

# For Secp256k1-TR (Bitcoin taproot compatible)
cargo run --bin trusted-dealer -- -t 2 -n 3 -C secp256k1-tr
```

The key packages will be written to files. Securely send the partipant's key
packages to them (or just proceed if you are running everything locally for
testing).

Start a signing run as the coordinator:

```
cargo run --bin coordinator -- -i 0.0.0.0 -p 2744 -n 2 -m message.raw -s sig.raw
```

This will start a server listening for connections to any IP using port 2744.
(These are the default values so feel free to omit them.) The protocol will run
with 2 participants, signing the message inside `message.raw` (replace as
appropriate). The signature will be written to `sig.raw`. The program will keep
running while it waits for the participants to connect to it.

Each participant should then run (or run in different terminals if you're
testing locally):

```
cargo run --bin participant -- -i 127.0.0.1 -p 2744 -k key-package-1.json
```

It will connect to the Coordinator using the given IP and port (replace as
needed), using the specified key package (again replace as needed).

Once two participants are running, the Coordinator should complete the protocol and
write the signature to specified file.

## Socket communication with server example

See the [Ywallet demo tutorial](https://frost.zfnd.org/zcash/ywallet-demo.html).


## Curve selection

Currently the demo supports curve Ed25519, RedPallas, and Secp256k1-TR. To use RedPallas, pass
`-C redpallas` to all commands (after `--`). When it's enabled, it will automatically
switch to Rerandomized FROST and it can be used to sign Zcash transactions.

To use Secp256k1-TR, pass `-C secp256k1-tr` to all commands (after `--`). When it's enabled,
it will automatically switch to Rerandomized FROST and it can be used to sign Bitcoin
taproot transactions.
