# SHRD container format

Version 2. All integers are big-endian. All lengths are in bytes.

A container is a cleartext header followed by a sequence of AES-256-GCM chunks. The payload
chunks carry the file; an optional final chunk carries the sender's signature.

```
+-----------------------+
|  header (cleartext)   |
+-----------------------+
|  chunk 0    payload   |
|  chunk 1    payload   |
|  ...                  |
|  chunk N    payload*  |   <- marked final
|  chunk N+1  trailer   |   <- only if the header says signed
+-----------------------+
```

## Header

### Common prologue (9 bytes)

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 4 | magic | `53 48 52 44` (`"SHRD"`) |
| 4 | 1 | version | `2` |
| 5 | 1 | mode | `1` = recipient, `2` = passphrase |
| 6 | 1 | suite | `1` = ML-KEM-768 + X25519 + ML-DSA-65 / HKDF-SHA256 / AES-256-GCM |
| 7 | 1 | chunkSizeLog | log2 of the plaintext chunk size; 12–26 inclusive |
| 8 | 1 | flags | bit 0 = signed, bit 1 = archive. All other bits MUST be zero |

A decryptor MUST reject a flags byte with any unknown bit set, rather than ignoring it: an
unknown flag could mean the container carries something this build would silently skip.

The **archive** bit says the plaintext is a tar archive that the encryptor built from a directory,
so a decryptor can unpack it without being told. It lives here, in the header, rather than in a
filename or a convention, because the header is covered by `headerHash` and therefore keys every
chunk: an attacker cannot set it on a container that was never an archive, and cannot clear it on
one that was. Unpacking runs untrusted input through a tar reader, so being unable to forge that
one bit matters.

### Mode 1 — recipient (total header 1129 bytes)

| Offset | Size | Field |
|---|---|---|
| 9 | 1088 | ML-KEM-768 ciphertext |
| 1097 | 32 | ephemeral X25519 public key |

### Mode 2 — passphrase (total header 37 bytes)

| Offset | Size | Field |
|---|---|---|
| 9 | 16 | Argon2id salt |
| 25 | 4 | Argon2id iterations (1–32) |
| 29 | 4 | Argon2id memory, KiB (8–1048576) |
| 33 | 4 | Argon2id lanes (1–64) |

The Argon2 costs are read from an untrusted file, so they are range-checked before any
allocation. A decryptor MUST reject values outside the ranges above, and MUST reject a memory
cost below `8 * lanes`.

## Identities

One identity covers both receiving and signing.

```
publicKeyBlob = mlkemPub(1184) || x25519Pub(32) || mldsaPub(1952)     // 3168 bytes
secretKeyBlob = mlkemSeed(64)  || x25519Scalar(32) || mldsaSeed(32)   //  128 bytes
```

The secret half is stored as seeds, so the whole identity is 128 bytes. A fingerprint is
`SHA-256(publicKeyBlob)` truncated to 8 bytes and printed as lowercase hex; it covers the whole
identity, not just one of the three keys, and is never used on the wire.

## Key derivation

`headerHash = SHA-256(header bytes)`

### Mode 1

```
(kemCt, ssKem)  = ML-KEM-768.Encaps(recipient.mlkemPub)
ephSk, ephPk    = X25519.KeyGen()
ssEcdh          = X25519(ephSk, recipient.x25519Pub)

fileKey = HKDF-SHA256(
    ikm  = ssKem || ssEcdh,                              // 64 bytes
    salt = headerHash,                                   // 32 bytes
    info = "SHROUD2 hybrid-kem v1" || recipientPublicKeyBlob,
    L    = 32)
```

Both secrets feed one extraction, so an attacker must break **both** ML-KEM-768 and X25519
to recover `fileKey`. `recipientPublicKeyBlob` is bound into `info`, which ties the derived key
to the intended recipient and prevents a captured encapsulation being replayed under a different
identity. `headerHash` as the salt binds the chunk size, suite, flags, KEM ciphertext and
ephemeral key.

> This is **not** X-Wing and is not wire-compatible with it. X-Wing's value is interoperability;
> this format has no interoperability requirement, so it uses an explicit HKDF combiner that is
> auditable in one function. See `KeyDerivation.ForRecipient`.

### Mode 2

```
master  = Argon2id(passphrase, salt, t, m, p, 32)
fileKey = HKDF-SHA256(ikm = master, salt = headerHash, info = "SHROUD2 passphrase v1", L = 32)
```

No public-key material is involved, which is why this mode needs no post-quantum primitive at
all: AES-256 and Argon2id are already quantum-resistant. Signing is available in this mode too,
and is the only part of it that uses a key pair.

## Chunks

Every chunk is self-describing on disk, and both framing fields are covered by the chunk's
associated data:

```
on the wire:  kind(1) || length(4) || ciphertext(length) || tag(16)

chunk_i = AES-256-GCM-Seal(
    key   = fileKey,
    nonce = 0x00000000 || uint64BE(i),                        // 12 bytes
    aad   = headerHash || uint64BE(i) || kind || int32BE(length),   // 45 bytes
    pt    = plaintext_i)
```

| `kind` | Meaning | Length constraint |
|---|---|---|
| 0 | payload, more follows | exactly `chunkSize` |
| 1 | payload, end of file | 0 to `chunkSize` |
| 2 | signature trailer | exactly 6477 |

Being self-describing is what lets the signature trailer follow the payload without the reader
needing to look ahead. Lengths are validated against these constraints **before** anything is
allocated or read, because they come from an untrusted file.

The chunk sequence MUST be exactly `payload* , final-payload , trailer?`, and nothing may follow
it. A trailer is required if and only if the header's signed flag is set.

**A container always has at least one chunk.** An empty plaintext produces a single final chunk
of 0 plaintext bytes plus a 16-byte tag.

### Why the nonce may be a bare counter

Nonce reuse is catastrophic for GCM, and a counter from zero is only safe because `fileKey` is
never reused across files:

- mode 1 draws a fresh ML-KEM encapsulation and a fresh ephemeral X25519 key per file;
- mode 2 draws a fresh 16-byte salt per file.

A given `(key, nonce)` pair therefore cannot recur.

### What the associated data buys

`aad = headerHash || index || kind || length` defeats the attacks a naive chunked design invites:

| Attack | Caught by |
|---|---|
| Flip a byte anywhere in the payload | GCM tag |
| Edit any header field | `headerHash` — in the AAD *and* in the key derivation |
| Drop trailing chunks (truncation) | `kind` — no surviving chunk claims to be final |
| Append data after the end | `kind` — the real final chunk is no longer last |
| Reorder or duplicate chunks | `index` |
| Splice chunks between two containers | `headerHash`, and a different `fileKey` |
| Edit the framing itself | `kind` and `length` are authenticated |
| Strip the signature | the signed flag is in `headerHash`, which keys every chunk |
| Claim a plain file is an archive | the archive flag is in `headerHash` too |

Each of these has a test in `tests/Shroud.Core.Tests/TamperTests.cs` and
`tests/Shroud.Core.Tests/SignatureTests.cs`, and each of those tests has been mutation-checked:
breaking the corresponding line of the implementation makes it fail.

## Signature trailer

Present only when the header's signed flag is set. The trailer is one further AEAD chunk, so the
sending identity is inside the encrypted region: it is visible to whoever can decrypt the
container, and to nobody else.

```
trailer plaintext = senderPublicKeyBlob(3168) || mldsa65Signature(3309)   // 6477 bytes
```

The signature is ML-DSA-65 (FIPS 204) in its **hedged** mode, which mixes fresh randomness into
each signature. Two signatures over the same message differ, and hedging is more robust against
fault and side-channel attacks than deterministic signing.

### What gets signed

What the signature covers matters more than the primitive:

```
signedMessage =
    "SHROUD2 signed-container v1"       // 27-byte domain separator
    || headerHash                       // 32
    || SHA-256(senderPublicKeyBlob)     // 32
    || recipientSlot                    // 32
    || SHA-256(plaintext)               // 32
    || int64BE(plaintextLength)         // 8
```

`recipientSlot` is `SHA-256(recipientPublicKeyBlob)` in mode 1, and 32 zero bytes in mode 2.

Each field is there for a reason:

- **`headerHash`** ties the signature to this exact container — its KEM ciphertext, Argon2 salt,
  chunk size and flags — so a signature cannot be lifted onto another file.
- **The sender's own key** is signed so the signature cannot be reinterpreted under a substituted
  verification key.
- **The recipient's key** is what stops surreptitious forwarding. Without it, Bob could take a
  container Alice sent him, re-encrypt the signed plaintext to Carol, and Carol would see a valid
  Alice signature on a message Alice never sent her. This is the Davis attack on naive
  sign-then-encrypt, and binding the recipient is the standard fix. Mode 2 signs an empty slot
  rather than omitting the field, so a trailer cannot be moved between the two modes either.
- **The plaintext hash and length** are the content commitment itself.

### Verification

A verifier MUST reject an unsigned container when the caller asked for a signature — checking the
header flag *before* doing any work, so that stripping a signature cannot have the container
quietly accepted as unsigned.

A valid signature on its own establishes only that the container is self-consistent: anyone can
generate an identity and sign with it. It says who sent the file only when the caller names the
identity it expects and that comparison succeeds.

## Encrypted key files

Secret keys are armoured text. An unprotected key file is
`shroud-secret-key:v2:<base64 of secretKeyBlob>`; a passphrase-protected one is
`shroud-secret-key-encrypted:v2:<base64 of the envelope below>`. Public keys are
`shroud-recipient:v2:<base64 of publicKeyBlob>`. Blank lines and `#` comments are ignored, so a key
file can carry a human-readable header.

The envelope is deliberately separate from the container format: it protects 128 bytes at rest
and has no need for chunking or signatures.

```
envelope = version(1) || salt(16) || t(4) || m(4) || p(4) || nonce(12)
           || ciphertext(128) || tag(16)                              // 185 bytes

key = Argon2id(passphrase, salt, t, m, p, 32)
ciphertext, tag = AES-256-GCM-Seal(
    key, nonce, secretKeyBlob,
    aad = "SHROUD2 key-file v1" || everything before the ciphertext)
```

Everything before the ciphertext is authenticated, so the Argon2 costs cannot be downgraded by
editing the file. They are also range-checked before any derivation. Key files default to
costlier Argon2 parameters than file encryption does (t=4, m=128 MiB, p=4): a key file is
unwrapped once per session, and it guards a long-lived secret rather than one file.

## Sizes

A payload of `n` bytes occupies `floor(n / chunkSize) + 1` chunks — the `+ 1` because the final
chunk may be empty, and a payload that is an exact multiple of the chunk size still needs one to
mark the end. Overhead is therefore `headerLength + 21 * (floor(n / chunkSize) + 1)`, plus `6498`
if signed.

At the default 1 MiB chunk size, a 5 MiB file encrypted to a recipient costs
`1129 + 21 * 6 = 1255` bytes, or `7753` bytes signed.

## Deliberate non-goals

- **No length hiding.** Plaintext length is recoverable from the container length to within one
  chunk, and the signature commits to the exact length. There is no padding.
- **No multi-recipient support.** One container, one recipient.
- **No trust model.** The format verifies that a container was signed by a given key. Deciding
  that the key belongs to a particular person is left to whoever compares fingerprints.
- **No revocation.** Nothing in a container expires, and there is no way to mark a key as retired.
