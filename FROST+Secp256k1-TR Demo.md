# FROST Tools with Secp256k1-TR Ciphersuite Demo

In the following examples:
- It's assumed that the tools have been built and are available in your `PATH`.
- JSON has been prettified for readability. The actual output will be compact JSON.

## Create a test directory

```bash
mkdir test
cd test
```

## Create the message to be signed

```bash
echo 'Hello, FROST!' > message.raw
cat message.raw

# This file has a newline at the end.
│ Hello, FROST!
```

## Use the trusted dealer to create key packages

```bash
trusted-dealer -t 2 -n 3 -C secp256k1-tr

│ Generating 3 shares with threshold 2...
│ Public key package written to public-key-package.json
│ Key package for participant 0000000000000000000000000000000000000000000000000000000000000001 written to key-package-1.json
│ Key package for participant 0000000000000000000000000000000000000000000000000000000000000002 written to key-package-2.json
│ Key package for participant 0000000000000000000000000000000000000000000000000000000000000003 written to key-package-3.json

cat public-key-package.json

│ {
│     "header": {
│         "version": 0,
│         "ciphersuite": "FROST-secp256k1-SHA256-TR-v1"
│     },
│     "verifying_shares": {
│         "0000000000000000000000000000000000000000000000000000000000000001": "03702e9224bdd1169575d44269601fd52a4808bf7c5445ccb81e53fe3c11f0163a",
│         "0000000000000000000000000000000000000000000000000000000000000002": "02d03500deb973f5402fba47af37a79300d6c8ed9c33ea1bcd2bb0f3e92d7072ce",
│         "0000000000000000000000000000000000000000000000000000000000000003": "02eef065f56180404b059f798eb71fa21a0873dce95c5de55cbf2af04dc5d71afe"
│     },
│     "verifying_key": "030a084c618139df23ac487555ef802b1fb534b8ad1f9c0b44dc5145a9d73c02da"
│ }

cat key-package-1.json

│ {
│     "header": {
│         "version": 0,
│         "ciphersuite": "FROST-secp256k1-SHA256-TR-v1"
│     },
│     "identifier": "0000000000000000000000000000000000000000000000000000000000000001",
│     "signing_share": "41ca9ee69700ad9235f1dfe7794fb4d587d8a0fa48d82b257f176f37acf4ff3a",
│     "commitment": [
│         "030a084c618139df23ac487555ef802b1fb534b8ad1f9c0b44dc5145a9d73c02da",
│         "02c47efdd884cb1d54bebdb48e13de12186fe66fc45bd9c9835fb0b5d96d9c3c8b"
│     ]
│ }

cat key-package-2.json

│ {
│     "header": {
│         "version": 0,
│         "ciphersuite": "FROST-secp256k1-SHA256-TR-v1"
│     },
│     "identifier": "0000000000000000000000000000000000000000000000000000000000000002",
│     "signing_share": "6ea65cdeb645b3b99d204f7f731e4bc88b171138d65bbe41f5688ca10a58ad9f",
│     "commitment": [
│         "030a084c618139df23ac487555ef802b1fb534b8ad1f9c0b44dc5145a9d73c02da",
│         "02c47efdd884cb1d54bebdb48e13de12186fe66fc45bd9c9835fb0b5d96d9c3c8b"
│     ]
│ }

cat key-package-3.json

│ {
│     "header": {
│         "version": 0,
│         "ciphersuite": "FROST-secp256k1-SHA256-TR-v1"
│     },
│     "identifier": "0000000000000000000000000000000000000000000000000000000000000003",
│     "signing_share": "9b821ad6d58ab9e1044ebf176cece2bb8e55817763df515e6bb9aa0a67bc5c04",
│     "commitment": [
│         "030a084c618139df23ac487555ef802b1fb534b8ad1f9c0b44dc5145a9d73c02da",
│         "02c47efdd884cb1d54bebdb48e13de12186fe66fc45bd9c9835fb0b5d96d9c3c8b"
│     ]
│ }
```

## Start a signing run as the coordinator

### Coordinator Terminal

```bash
coordinator -n 2 -m message.raw -s sig.raw -C secp256k1-tr

│ Reading public key package from public-key-package.json
│ Reading message from message.raw...
│ Processing randomizer []
│ Waiting for participants to send their commitments...
```

### Round 1: Participants send their commitments, coordinator sends signing package

#### Participant 1 Terminal

```bash
participant -k key-package-1.json -C secp256k1-tr

│ Reading key package from key-package-1.json
│ Connected to server at [1.R.0] 127.0.0.1:443
```

#### Coordinator Terminal

```bash
│ Client connected
│ Received:
│ {
│     "IdentifiedCommitments": {
│         "identifier": "0000000000000000000000000000000000000000000000000000000000000001",
│         "commitments": {
│             "header": {
│                 "version": 0,
│                 "ciphersuite": "FROST-secp256k1-SHA256-TR-v1"
│             },
│             "hiding": "03bd14dead9b2f4c1d71f767a3e49d419d0fd1c5d757651a714a58d9f4bbe8780b",
│             "binding": "03cd869a474e146841bf7cc08d026a7c66b23c629034454650f5c6bcb37e8e6b7e"
│         }
│     }
│ }
```

#### Participant 2 Terminal

```bash
participant -k key-package-2.json -C secp256k1-tr

│ Reading key package from key-package-2.json
│ Connected to server at [1.R.0] 127.0.0.1:443
```

#### Coordinator Terminal

```bash
│ Client connected
│ Received:
│ {
│     "IdentifiedCommitments": {
│         "identifier": "0000000000000000000000000000000000000000000000000000000000000002",
│         "commitments": {
│             "header": {
│                 "version": 0,
│                 "ciphersuite": "FROST-secp256k1-SHA256-TR-v1"
│             },
│             "hiding": "02a13fc1a825bb83d1e17818389fea13056bb531ed0b7619c2001ee104de817b00",
│             "binding": "0293f554a9069b668124a077b64d612929cfae98aee55c29a4867d403e38180a3e"
│         }
│     }
│ }
│ Sending SigningPackage to participants...
│ Waiting for participants to send their SignatureShares...
```

### Round 2: Participants partially sign the messagem, coordinator finalizes the signature

#### Participant 1 Terminal

```bash
│ Received:
│ {
│     "SigningPackageAndRandomizer": {
│         "signing_package": {
│             "header": {
│                 "version": 0,
│                 "ciphersuite": "FROST-secp256k1-SHA256-TR-v1"
│             },
│             "signing_commitments": {
│                 "0000000000000000000000000000000000000000000000000000000000000001": {
│                     "header": {
│                         "version": 0,
│                         "ciphersuite": "FROST-secp256k1-SHA256-TR-v1"
│                     },
│                     "hiding": "03bd14dead9b2f4c1d71f767a3e49d419d0fd1c5d757651a714a58d9f4bbe8780b",
│                     "binding": "03cd869a474e146841bf7cc08d026a7c66b23c629034454650f5c6bcb37e8e6b7e"
│                 },
│                 "0000000000000000000000000000000000000000000000000000000000000002": {
│                     "header": {
│                         "version": 0,
│                         "ciphersuite": "FROST-secp256k1-SHA256-TR-v1"
│                     },
│                     "hiding": "02a13fc1a825bb83d1e17818389fea13056bb531ed0b7619c2001ee104de817b00",
│                     "binding": "0293f554a9069b668124a077b64d612929cfae98aee55c29a4867d403e38180a3e"
│                 }
│             },
│             "message": "48656c6c6f2c2046524f5354210a"
│         },
│         "randomizer": null
│     }
│ }
│ Message to be signed (hex-encoded):
│ 48656c6c6f2c2046524f5354210a
│ Do you want to sign it? (y/n)

y

| Done
```

#### Participant 2 Terminal

```bash
│ Received:
│ {
│     "SigningPackageAndRandomizer": {
│         "signing_package": {
│             "header": {
│                 "version": 0,
│                 "ciphersuite": "FROST-secp256k1-SHA256-TR-v1"
│             },
│             "signing_commitments": {
│                 "0000000000000000000000000000000000000000000000000000000000000001": {
│                     "header": {
│                         "version": 0,
│                         "ciphersuite": "FROST-secp256k1-SHA256-TR-v1"
│                     },
│                     "hiding": "03bd14dead9b2f4c1d71f767a3e49d419d0fd1c5d757651a714a58d9f4bbe8780b",
│                     "binding": "03cd869a474e146841bf7cc08d026a7c66b23c629034454650f5c6bcb37e8e6b7e"
│                 },
│                 "0000000000000000000000000000000000000000000000000000000000000002": {
│                     "header": {
│                         "version": 0,
│                         "ciphersuite": "FROST-secp256k1-SHA256-TR-v1"
│                     },
│                     "hiding": "02a13fc1a825bb83d1e17818389fea13056bb531ed0b7619c2001ee104de817b00",
│                     "binding": "0293f554a9069b668124a077b64d612929cfae98aee55c29a4867d403e38180a3e"
│                 }
│             },
│             "message": "48656c6c6f2c2046524f5354210a"
│         },
│         "randomizer": null
│     }
│ }
│ Message to be signed (hex-encoded):
│ 48656c6c6f2c2046524f5354210a
│ Do you want to sign it? (y/n)

y

| Done
```

#### Coordinator Terminal

```bash
│ Received:
│ {
│     "SignatureShare": {
│         "header": {
│             "version": 0,
│             "ciphersuite": "FROST-secp256k1-SHA256-TR-v1"
│         },
│         "share": "ecc9bd2da863382fe3221f31f6cff2e4d0efb5a147560fc741cb8c9161b28efe"
│     }
│ }
│ Client disconnected
│ Received:
│ {
│     "SignatureShare": {
│         "header": {
│             "version": 0,
│             "ciphersuite": "FROST-secp256k1-SHA256-TR-v1"
│         },
│         "share": "f3d48398c75ceddda791b77ad92dc6f306884cdfacafb56fb4a57e9e482cd510"
│     }
│ }
│ Client disconnected
│ Raw signature written to sig.raw

xxd -p sig.raw

│ 0f4f89c3fb40dafe7d70334c325b2b80f2afc5f350174f63d60fcb56566a
│ 6f3ae09e40c66fc0260d8ab3d6accffdb9d91cc9259a44bd24fb369eaca2
│ d9a922cd
```
