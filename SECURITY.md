# Security policy

## Reporting a vulnerability

Report privately through GitHub's
[private vulnerability reporting](https://github.com/jakoreilly/Shroud/security/advisories/new)
rather than opening a public issue.

Useful things to include, as far as you have them: which version or commit, what an attacker
needs to be able to do first, and what they get out of it. A failing test or a container that
reproduces the problem is worth more than a description.

There is no bounty and no response-time commitment — this is a personal project.

## Scope

shroud is **not audited**, and the container format is purpose-built rather than standardised.
[Known limitations](README.md#known-limitations) lists what is already understood to be weak or
absent; a report that restates one of those is not a vulnerability, though a concrete attack that
is worse than the limitation admits certainly is.

Most interesting are breaks in what the format claims to do: recovering a file key, forging or
lifting a signature, getting a tampered container to decrypt without error, escaping the
destination directory during archive extraction, or reading a secret key from disk without its
passphrase.

## Supported versions

The most recent release only. There is no backporting.
