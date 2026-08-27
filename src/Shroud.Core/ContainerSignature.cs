using System.Buffers.Binary;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Shroud.Core;

/// <summary>
/// ML-DSA-65 signatures over a container.
///
/// The signature is carried inside the encrypted region, so the sender's identity is not visible
/// to an observer holding the container -- only to whoever can decrypt it.
///
/// What gets signed matters more than the primitive. The signed message binds:
///
///   - the header hash, which ties the signature to this exact container (its KEM ciphertext,
///     Argon2 salt, chunk size and flags), so a signature cannot be lifted onto another file;
///   - the sender's own public key, so the signature cannot be reinterpreted under a substituted
///     verification key;
///   - the RECIPIENT's public key, which is what stops surreptitious forwarding: without it, Bob
///     could take a container Alice sent him, re-encrypt the signed plaintext to Carol, and Carol
///     would see a valid Alice signature on a message Alice never sent her. This is the Davis
///     attack on naive sign-then-encrypt, and binding the recipient is the standard fix;
///   - the SHA-256 and the length of the plaintext, which is the content commitment itself.
/// </summary>
internal static class ContainerSignature
{
    /// <summary>Recipient slot for passphrase-mode containers, which have no recipient key.</summary>
    private static readonly byte[] NoRecipient = new byte[ShroudFormat.HashLength];

    public static byte[] BuildTrailer(
        ShroudSecretKey sender,
        ShroudPublicKey? recipient,
        byte[] headerHash,
        byte[] plaintextHash,
        long plaintextLength)
    {
        var senderBlob = sender.GetPublicKey().ToBlob();
        var message = BuildSignedMessage(senderBlob, recipient, headerHash, plaintextHash, plaintextLength);

        // deterministic: false selects FIPS 204's hedged signing, which mixes in fresh randomness
        // and is the recommended default -- it is more robust against fault and side-channel
        // attacks than deterministic signing.
        var signer = new MLDsaSigner(MLDsaParameters.ml_dsa_65, deterministic: false);
        signer.Init(forSigning: true, sender.MlDsa);
        signer.BlockUpdate(message);
        var signature = signer.GenerateSignature();

        if (signature.Length != ShroudFormat.MlDsaSignatureLength)
            throw new InvalidOperationException($"Unexpected ML-DSA-65 signature length {signature.Length}.");

        var trailer = new byte[ShroudFormat.SignatureTrailerLength];
        senderBlob.CopyTo(trailer, 0);
        signature.CopyTo(trailer, ShroudFormat.PublicKeyBlobLength);
        return trailer;
    }

    /// <summary>
    /// Verifies a trailer and returns the sender's identity. Throws if the signature does not
    /// verify, or if <paramref name="expectedSender"/> is given and does not match.
    /// </summary>
    public static ShroudPublicKey VerifyTrailer(
        byte[] trailer,
        ShroudPublicKey? recipient,
        ShroudPublicKey? expectedSender,
        byte[] headerHash,
        byte[] plaintextHash,
        long plaintextLength)
    {
        if (trailer.Length != ShroudFormat.SignatureTrailerLength)
            throw new ShroudSignatureException("Signature trailer has the wrong length.");

        var senderBlob = trailer[..ShroudFormat.PublicKeyBlobLength];
        var signature = trailer[ShroudFormat.PublicKeyBlobLength..];

        // Check the expected sender before spending time on the signature, and compare the whole
        // identity blob rather than just the verification key.
        if (expectedSender is not null && !expectedSender.BlobEquals(senderBlob))
        {
            throw new ShroudSignatureException(
                $"Container was signed by {ShroudPublicKey.Fingerprint(senderBlob)}, "
                    + $"but {expectedSender.Fingerprint()} was expected.");
        }

        var sender = ShroudPublicKey.FromBlob(senderBlob);
        var message = BuildSignedMessage(senderBlob, recipient, headerHash, plaintextHash, plaintextLength);

        var verifier = new MLDsaSigner(MLDsaParameters.ml_dsa_65, deterministic: false);
        verifier.Init(forSigning: false, sender.MlDsa);
        verifier.BlockUpdate(message);

        if (!verifier.VerifySignature(signature))
        {
            throw new ShroudSignatureException(
                $"Signature does not verify against the sending key {sender.Fingerprint()}. "
                    + "The container was modified, or it was re-encrypted to a different recipient.");
        }

        return sender;
    }

    private static byte[] BuildSignedMessage(
        byte[] senderBlob,
        ShroudPublicKey? recipient,
        byte[] headerHash,
        byte[] plaintextHash,
        long plaintextLength)
    {
        var context = ShroudFormat.SignatureContext;
        var message = new byte[context.Length + (4 * ShroudFormat.HashLength) + sizeof(long)];
        var cursor = message.AsSpan();

        context.CopyTo(cursor);
        cursor = cursor[context.Length..];

        headerHash.CopyTo(cursor);
        cursor = cursor[ShroudFormat.HashLength..];

        SHA256.HashData(senderBlob).CopyTo(cursor);
        cursor = cursor[ShroudFormat.HashLength..];

        (recipient is null ? NoRecipient : SHA256.HashData(recipient.ToBlob())).CopyTo(cursor);
        cursor = cursor[ShroudFormat.HashLength..];

        plaintextHash.CopyTo(cursor);
        cursor = cursor[ShroudFormat.HashLength..];

        BinaryPrimitives.WriteInt64BigEndian(cursor, plaintextLength);

        return message;
    }
}
