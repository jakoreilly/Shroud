# Using shroud

Instructions and working practice for the `shroud` command. `README.md` explains what the tool is
and what it deliberately does not do; `FORMAT.md` is the wire format.

## Install

```
dotnet publish src/Shroud.Cli -c Release -o dist
```

That produces `dist/shroud` (`dist/shroud.exe` on Windows) alongside its four DLLs — `shroud`,
`Shroud.App`, `Shroud.Core`, and BouncyCastle. Put the directory on your `PATH`, or invoke it by
path. There is no installer, no service, and no network access at any point.

If you would rather click than type, there is a desktop UI covering the same ground:

```
dotnet publish src/Shroud.Ui -c Release -o dist-ui
```

Everything below is the CLI. The two front ends share one engine and agree by construction on
what a signature means, so nothing here is UI-only or CLI-only behaviour.

## The five-minute version

Two people, Alice and Bob. Each sets up their machine **once**:

```
shroud keygen                      # prompts for a passphrase; writes ~/.shroud/identity.{key,pub}
```

That identity is now the default: shroud signs with it unless you pass `--no-sign`.

They exchange the `.pub` files — email, chat, a shared drive, anywhere — then confirm the
fingerprints by some *other* route (a phone call, an in-person check, an existing authenticated
channel) and record the result:

```
shroud contacts add --in bob.pub --name bob --fingerprint d83c9fbfed01dd22
```

`contacts add` refuses unless the fingerprint you type matches the key in the file. That is the
whole ceremony, and it happens once per person rather than once per file.

Alice sends Bob a file:

```
shroud encrypt --in q3-results.xlsx --out q3.shroud --recipient bob
```

Bob decrypts it:

```
shroud decrypt --in q3.shroud --out q3-results.xlsx --key ~/.shroud/identity.key
```

If that prints `signature OK, from your verified contact alice (...)`, the file is Alice's,
unmodified, and was addressed to Bob specifically. If it says the signer is **not one of your
contacts**, someone other than Alice signed it. Anything else is a failure — check the exit code,
do not squint at the output.

## Commands

```
shroud keygen      [--out <basename>] [--plaintext-key] [--force]
shroud encrypt     --in <f|dir> --out <f> (--recipient <name|f.pub> | --passphrase)
                [--sign <f.key> | --no-sign] [--chunk-size-log <n>] [--force]
shroud decrypt     --in <f> --out <f|dir> (--key <f.key> | --passphrase)
                [--sender <name|f.pub>] [--require-signed] [--no-extract] [--force]
shroud verify      --in <f> (--key <f.key> | --passphrase) [--sender <name|f.pub>]
shroud info        --in <f>
shroud contacts    list | add --in <f.pub> --name <n> --fingerprint <fp> | remove --name <n>
shroud passwd      [--key <f.key>] [--plaintext-key]
shroud fingerprint --in <name|f.pub|f.key>
```

Short forms: `-i` `--in`, `-o` `--out`, `-r` `--recipient`, `-k` `--key`, `-s` `--sign`,
`-p` `--passphrase`, `-f` `--force`.

Details that are easy to miss:

- **`--sign` takes a secret key, `--sender` takes a public key or a contact name.** Signing is
  something only you can do; verifying is something anyone can do.
- **`--sender` implies `--require-signed`.** Asking who sent a file will never quietly accept one
  that nobody signed.
- **`--passphrase-file` implies `--passphrase`.** You do not need both.
- **`--recipient` and `--sender` accept a contact name** wherever they accept a path. A name is
  always printed with its fingerprint, because the name is only as good as the check behind it.
- **Signing is automatic** once you have a default identity. `--no-sign` opts out per command.

Nothing is overwritten without `--force` — output files, directories being unpacked into, and
`keygen`.

## Key management

### Generating

```
shroud keygen                  # your default identity, in ~/.shroud
shroud keygen --out alice      # a named pair beside you, for a second identity
```

One identity both receives files and signs them; there is no separate signing key. The default
identity is the one shroud signs with automatically, so `shroud keygen` on its own is the whole setup
step on a new machine. The secret key
is passphrase-protected by default (Argon2id, t=4, m=128 MiB, p=4) and the file is restricted to
your user account. `keygen` prints the fingerprint — record it somewhere durable now, not later.

`--plaintext-key` writes the secret unprotected. It warns when it does. Use it only where
something else is providing the protection (see *Automation*), never on a laptop.

### Backing up

**There is no recovery.** No escrow, no key derivation from a mnemonic, no support line. Lose
`alice.key` and every container encrypted to `alice.pub` is gone permanently.

Back up the key file the way you would back up any other irreplaceable secret: at least two
copies, offline, in different places, each protected by a passphrase you have also backed up.
The file is under 300 bytes, so a printed base64 block in a safe is a legitimate option.

### Distributing and verifying public keys

The `.pub` file is not secret and needs no protection in transit. What it does need is
**authentication**: an attacker who swaps Bob's `.pub` for their own reads everything sent to
"Bob" from then on.

So compare fingerprints over a channel the key did not travel on:

```
shroud fingerprint --in bob.pub
d83c9fbfed01dd22
```

Sixteen hex digits, read aloud in four groups of four, is a thirty-second phone call. That call
is the entire trust model — shroud has no PKI, no key servers, and no web of trust to fall back on.

Then record it, so the call never has to happen twice:

```
shroud contacts add --in bob.pub --name bob --fingerprint d83c9fbfed01dd22
shroud contacts list
bob                      d83c9fbfed01dd22
```

`--fingerprint` is required, and the command fails if it does not match the key in the file. That
refusal is the feature: a mismatch means the key you received is not the key they sent.

From then on `bob` works anywhere a `.pub` path does, and shroud recognises Bob's signature on
incoming files without being asked:

```
shroud encrypt --in q3.xlsx --out q3.shroud --recipient bob
shroud decrypt --in from-bob.shroud --out q3.xlsx --key ~/.shroud/identity.key
shroud: signature OK, from your verified contact bob (d83c9fbfed01dd22)
```

Contacts are ordinary `.pub` files in `~/.shroud/contacts`, so you can inspect, copy and back them
up like anything else. Remove one with `shroud contacts remove --name bob`.

**The store is not tamper-proof.** Anyone who can write to your home directory can swap a
contact's key, which is why every command prints the fingerprint next to the name. If a familiar
name ever shows an unfamiliar fingerprint, stop.

### Rotating and retiring

There is no revocation. If a secret key is exposed:

1. Generate a new identity, and distribute and verify the new `.pub` as above.
2. Tell everyone who holds the old `.pub` to stop using it, out of band.
3. Decrypt anything still needed with the old key and re-encrypt to the new one.
4. Keep the old key file only as long as step 3 needs it, then destroy it.

Containers already sent cannot be recalled, and an attacker holding the old key can still read
anything they captured. Rotation limits future damage only. Plan for that when you decide how
long-lived an identity should be.

### Changing a key passphrase

```
shroud passwd --key alice.key                 # prompts for the old, then twice for the new
shroud passwd --key alice.key --plaintext-key # removes protection entirely
```

`passwd` writes `alice.key.new` beside the original and swaps it in, so an interrupted run cannot
destroy your only copy.

## Everyday recipes

**Send a file to someone, signed** — the normal case, once you both have identities and contacts:

```
shroud encrypt --in report.pdf --out report.shroud --recipient bob
shroud decrypt --in report.shroud --out report.pdf --key ~/.shroud/identity.key --sender alice
```

`--sender alice` pins the expected signer and fails with exit 3 if anyone else signed it. Leaving
it off still identifies a known contact by name — the difference is that pinning turns a surprise
into an error instead of a line of output you might not read.

**Encrypt your own files at rest** — no keys to manage:

```
shroud encrypt --in taxes-2025.zip --out taxes-2025.shroud --passphrase
shroud decrypt --in taxes-2025.shroud --out taxes-2025.zip --passphrase
```

**Encrypt a whole directory** — pass the directory and shroud packs it for you:

```
shroud encrypt --in ./records --out records.shroud --recipient bob
shroud decrypt --in records.shroud --out ./records-restored --key ~/.shroud/identity.key
```

The directory becomes a tar archive, and the header records that it is one — in authenticated
bytes, not in the filename — so the decrypting side unpacks it without being told. Add
`--no-extract` to get the raw tar instead.

Two things worth knowing. Packing writes a temporary tar next to `--out`, so that volume needs
room for the whole directory as well as the container; it is deleted however the command ends.
And extraction refuses any entry that would land outside the destination, along with symlinks and
every other non-plain entry type, because an archive from someone else is untrusted input no
matter who signed it.

**Check what a container is without decrypting it:**

```
shroud info --in report.shroud
```

`info` needs no key. It reports the mode, the chunk size, whether the container is signed, and —
for passphrase mode — the Argon2 costs. It will *not* tell you who signed it: the sending identity
is inside the encrypted region, which is a privacy property, not an omission. `info` proves
nothing about authenticity; only a successful `decrypt --sender` does.

**Check a container is intact and from who you think, without unpacking it:**

```
shroud verify --in report.shroud --key ~/.shroud/identity.key --sender alice
report.shroud: intact, single file
```

`verify` still has to decrypt — the signature is inside the encrypted region — but the plaintext
is discarded rather than written anywhere. Same exit codes as `decrypt`, so it drops into a script
as a gate before you commit to the real thing.

Never point `--out` at `/dev/null` or `NUL` to fake this: shroud stages its output beside the
destination and renames it into place, which would replace the device node.

## Automation

### Exit codes

| Code | Meaning | What a script should do |
|---|---|---|
| 0 | Success | Continue |
| 2 | Malformed, truncated, tampered, or wrong key/passphrase | Treat the file as untrusted; alert |
| 3 | Signature missing, invalid, or from an unexpected sender | Treat the file as **hostile**; alert |
| 64 | Usage error — bad options | Fix the invocation; this is a bug in your script |
| 74 | I/O error — missing file, permissions, disk | Retry or escalate |

Codes 2 and 3 are deliberately distinct: "this file is damaged" and "this file is not from who
you think" call for different responses.

### Supplying passphrases without a prompt

In order of precedence: `--passphrase-file` / `--key-passphrase-file`, then the environment
(`SHROUD_PASSPHRASE` for files, `SHROUD_KEY_PASSPHRASE` for key files), then an interactive prompt. If
input is redirected and no file or variable is set, shroud fails with a usage error rather than
hanging.

Prefer a passphrase **file** over an environment variable: environment blocks are visible to
other processes on some systems and leak into crash dumps, child processes, and CI logs. A file
you write with restrictive permissions, read once, and delete is easier to reason about.

```bash
umask 077
secrets-manager read shroud/bob-key > "$RUNTIME_DIR/shroud.pass"
shroud decrypt --in intake.shroud --out intake.csv \
    --key /etc/shroud/bob.key --key-passphrase-file "$RUNTIME_DIR/shroud.pass" \
    --sender partner.pub
status=$?
shred -u "$RUNTIME_DIR/shroud.pass" 2>/dev/null || rm -f "$RUNTIME_DIR/shroud.pass"
exit $status
```

### A hardened intake script

```bash
#!/usr/bin/env bash
set -euo pipefail

infile=$1
outfile=$2

# Capture the status explicitly. Inside `if ! cmd; then`, $? is the status of the negation,
# not of the command, so the case below would never match.
status=0
shroud decrypt --in "$infile" --out "$outfile" \
    --key /etc/shroud/intake.key --sender /etc/shroud/partner.pub || status=$?

if [ "$status" -ne 0 ]; then
    case $status in
        2) logger -p auth.crit "shroud: $infile is corrupt or was tampered with" ;;
        3) logger -p auth.crit "shroud: $infile is not from the expected partner" ;;
        *) logger -p auth.err  "shroud: $infile failed to decrypt" ;;
    esac
    exit 1
fi
```

Note what this does **not** do: it never falls back to decrypting without `--sender`, and it never
treats a failure as "probably fine, retry later". A signature failure on an inbound file is a
security event.

### PowerShell

```powershell
$env:SHROUD_KEY_PASSPHRASE = (Get-Secret -Name ShroudIntakeKey -AsPlainText)
shroud decrypt --in intake.shroud --out intake.csv --key intake.key --sender partner.pub
if ($LASTEXITCODE -ne 0) { throw "shroud failed with $LASTEXITCODE" }
Remove-Item Env:\SHROUD_KEY_PASSPHRASE
```

### Where things live

Your identity and contacts are under `~/.shroud`, or wherever `SHROUD_HOME` points. Setting `SHROUD_HOME`
per job is the clean way to give a service account its own identity and its own contact list
without touching a human's:

```bash
export SHROUD_HOME=/etc/shroud/intake
shroud verify --in "$infile" --key "$SHROUD_HOME/identity.key" --sender partner
```

### Known automation gap

`shroud passwd` reads the **new** passphrase from an interactive prompt only — neither
`--key-passphrase-file` nor `SHROUD_KEY_PASSPHRASE` applies to it. Adding or changing key protection
therefore cannot be scripted today. Removing it (`--plaintext-key`) can. For unattended rotation,
generate a fresh identity with `keygen` (which does honour the environment variable) rather than
re-protecting an existing key.

## Best practice

**Do**

- Add people as contacts, with `--fingerprint`, before you exchange anything real. It is the only
  step in the whole tool that establishes who anyone is.
- Pass `--sender` on every decrypt where you know who sent the file. Being *told* the signer is a
  known contact is good; declaring who you expect turns a surprise into a non-zero exit.
- Use `--require-signed` when you accept files from several known parties, and read the name and
  fingerprint shroud reports.
- Verify fingerprints out of band before trusting a `.pub` for the first time.
- Use `shroud verify` as a gate before acting on a file, rather than decrypting and hoping.
- Keep secret keys passphrase-protected, and keep the passphrase somewhere different from the key.
- Use a separate identity per environment and per counterparty relationship. Blast radius is the
  only real defence available given there is no revocation.
- Check exit codes in scripts. Never `|| true` a decrypt.
- Keep the default 1 MiB chunk size unless you have measured a reason not to.
- Decrypt somewhere you control. Staging and cleanup use ordinary file operations, not secure
  erase.

**Do not**

- Do not treat `shroud info` as evidence of anything. It reads unauthenticated header bytes.
- Do not ignore the `container is UNSIGNED` warning on files that are supposed to be signed —
  that is exactly what a stripped signature looks like from the outside.
- Do not accept a contact whose fingerprint does not match, "just this once", by editing
  `~/.shroud/contacts` by hand. That file is the trust store.
- Do not unpack an archive from an unverified sender into a directory that matters. Extraction
  refuses traversal and symlinks, but the *contents* are still whatever they sent you.
- Do not put a passphrase on a command line. There is no `--passphrase=...` option, and this is
  why: command lines are visible in the process table and in shell history.
- Do not use `--plaintext-key` on an interactive machine.
- Do not send the `.pub` and its fingerprint through the same channel.
- Do not reuse one identity for both "receives production data" and "signs test artefacts".
- Do not assume deleting the plaintext afterwards is enough on SSDs, copy-on-write filesystems, or
  anything with snapshots.

## Reading the output

| Message | Meaning |
|---|---|
| `signature OK, from the expected sender <name> (<fp>)` | Everything checked out. This is the only fully good outcome. |
| `signature OK, from your verified contact <name> (<fp>)` | The signer is a key whose fingerprint you confirmed when you added them. As strong as the line above; you just did not say in advance who to expect. |
| `signature is internally valid, signed by <fp>` + `sender identity NOT checked` | Signed by a key that is not one of your contacts. Compare `<fp>` yourself, or add them properly. |
| `container is UNSIGNED` | Nothing establishes who produced this file. |
| `SIGNATURE: Container was signed by X, but Y was expected` | Wrong sender. Exit 3. Treat as hostile. |
| `SIGNATURE: Container is not signed, but a verified signature was required` | Exit 3. Possibly a stripped signature. |
| `Authentication failed on the first chunk` | Wrong key, wrong passphrase, or a corrupt header. |
| `Authentication failed on chunk N` | The container was modified or truncated after that point. |
| `Container is truncated: no chunk was marked as the end of the payload` | Incomplete file — a failed transfer looks like this. |
| `Not a Shroud container (bad magic)` | Not a shroud file at all. |
| `ARCHIVE: ... outside the destination directory` | The archive tried to write outside where you told it to. Exit 2. Treat the sender as hostile. |
| `ARCHIVE: ... leaves the destination directory` | The destination already contained a link pointing elsewhere, and the archive tried to reach out through it. Exit 2. Treat the sender as hostile. |
| `Fingerprint mismatch` | The key in the file is not the one you were told to expect. Do not add it. |

On any failure the output file is not created and no partial plaintext is left behind: shroud writes
to a staging file beside the destination and renames it into place only after everything, the
signature included, has verified.

## Operational notes

- **Disk space.** The staging file *is* the output, renamed, so only one copy of the plaintext is
  ever written. Budget for the container plus the plaintext, and note that the staging file is
  created next to `--out` — so that volume is the one that needs the room.
- **Memory** is one chunk (1 MiB by default) regardless of file size, plus the Argon2 working set
  in passphrase mode: 64 MiB for files, 128 MiB for key files. Size containers accordingly on
  memory-capped hosts.
- **Time.** Bulk encryption runs at roughly disk speed (~430 MB/s encrypt, ~400 MB/s decrypt on a
  laptop). Argon2id dominates small operations: about 0.7 s per file in passphrase mode and about
  1.2 s to open a protected key file. A loop over ten thousand small files in passphrase mode will
  spend two hours in Argon2 alone — encrypt an archive instead.
- **Chunk size** (`--chunk-size-log`, 12–26, default 20 = 1 MiB) trades memory against per-chunk
  overhead of 21 bytes. Smaller chunks matter only for memory-constrained streaming; larger ones
  save a negligible amount of space.
- **Interrupted runs** leave a `*.shroud-partial` or `*.shroud-archive` file only if shroud is killed
  outright (SIGKILL, power loss). Ordinary failures clean up after themselves. Those files are
  safe to delete.
- **Filenames and sizes are not hidden.** The container reveals its plaintext length to within one
  chunk, and the name you give `--out` is yours to choose carefully.
