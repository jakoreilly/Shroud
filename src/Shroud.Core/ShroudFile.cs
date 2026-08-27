using System.Security.Cryptography;

namespace Shroud.Core;

/// <summary>What a decryption established about the container's origin.</summary>
/// <param name="WasSigned">Whether the container carried a signature at all.</param>
/// <param name="Sender">The verified sending identity, or null for an unsigned container.</param>
/// <param name="IsArchive">Whether the plaintext is a tar archive that shroud built from a directory.</param>
/// <param name="SenderWasExpected">
/// True only when the caller named an expected sender and the signature matched it. When false on
/// a signed container, the signature is valid but says nothing about <em>who</em> sent it -- any
/// key can produce a valid signature over its own message.
/// </param>
public sealed record DecryptionResult(bool WasSigned, ShroudPublicKey? Sender, bool SenderWasExpected, bool IsArchive)
{
    public string? SenderFingerprint => Sender?.Fingerprint();
}

/// <summary>How strictly a decryption should treat signatures.</summary>
public sealed record VerificationPolicy
{
    /// <summary>Verify a signature if present; accept an unsigned container.</summary>
    public static VerificationPolicy Optional { get; } = new();

    /// <summary>The identity the container must be signed by. Implies <see cref="RequireSignature"/>.</summary>
    public ShroudPublicKey? ExpectedSender { get; init; }

    /// <summary>Reject unsigned containers. Set this to prevent signature-stripping.</summary>
    public bool RequireSignature { get; init; }

    public static VerificationPolicy From(ShroudPublicKey expectedSender) =>
        new() { ExpectedSender = expectedSender, RequireSignature = true };

    public static VerificationPolicy Required { get; } = new() { RequireSignature = true };
}

/// <summary>Encrypts and decrypts SHROUD containers. This is the whole public surface.</summary>
public static class ShroudFile
{
    /// <summary>
    /// Encrypts to a recipient's public key using the hybrid ML-KEM-768 + X25519 KEM. Pass
    /// <paramref name="sender"/> to add an ML-DSA-65 signature proving who produced the container,
    /// and <paramref name="archive"/> to record that the plaintext is a tar archive.
    /// </summary>
    public static void Encrypt(
        Stream plaintext,
        Stream output,
        ShroudPublicKey recipient,
        ShroudSecretKey? sender = null,
        byte chunkSizeLog = ShroudFormat.DefaultChunkSizeLog,
        bool archive = false)
    {
        ValidateChunkSizeLog(chunkSizeLog);

        var encapsulation = HybridKem.Encapsulate(recipient);
        var header = FileHeader.ForRecipient(
            encapsulation.KemCiphertext,
            encapsulation.EphemeralPublicKey,
            chunkSizeLog,
            signed: sender is not null,
            archive);

        var headerBytes = header.ToBytes();
        var headerHash = SHA256.HashData(headerBytes);
        var fileKey = KeyDerivation.ForRecipient(encapsulation.SharedSecret, recipient, headerHash);

        try
        {
            output.Write(headerBytes);
            Seal(plaintext, output, fileKey, headerHash, header.ChunkSize, sender, recipient);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fileKey);
        }
    }

    /// <summary>Decrypts a recipient-mode container and reports what was established about its origin.</summary>
    public static DecryptionResult Decrypt(
        Stream input,
        Stream output,
        ShroudSecretKey secretKey,
        VerificationPolicy? policy = null)
    {
        var header = FileHeader.Read(input);
        if (header.Mode != ShroudFormat.ModeRecipient)
            throw new ShroudFormatException("This container is passphrase-encrypted; supply a passphrase, not a key file.");

        var recipient = secretKey.GetPublicKey();
        var hybridSecret = HybridKem.Decapsulate(
            secretKey,
            header.KemCiphertext!,
            header.EphemeralX25519PublicKey!);

        var headerHash = header.ComputeHash();
        var fileKey = KeyDerivation.ForRecipient(hybridSecret, recipient, headerHash);

        try
        {
            return Open(input, output, fileKey, header, headerHash, recipient, policy);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fileKey);
        }
    }

    /// <summary>Encrypts under a passphrase stretched with Argon2id. No public-key material is required.</summary>
    public static void EncryptWithPassphrase(
        Stream plaintext,
        Stream output,
        string passphrase,
        ShroudSecretKey? sender = null,
        Argon2Settings? argon2 = null,
        byte chunkSizeLog = ShroudFormat.DefaultChunkSizeLog,
        bool archive = false)
    {
        ArgumentException.ThrowIfNullOrEmpty(passphrase);
        ValidateChunkSizeLog(chunkSizeLog);

        var settings = argon2 ?? Argon2Settings.Default;
        settings.Validate();

        var header = FileHeader.ForPassphrase(
            RandomNumberGenerator.GetBytes(ShroudFormat.SaltLength),
            settings,
            chunkSizeLog,
            signed: sender is not null,
            archive);

        var headerBytes = header.ToBytes();
        var headerHash = SHA256.HashData(headerBytes);
        var fileKey = KeyDerivation.ForPassphrase(passphrase, header);

        try
        {
            output.Write(headerBytes);
            Seal(plaintext, output, fileKey, headerHash, header.ChunkSize, sender, recipient: null);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fileKey);
        }
    }

    /// <summary>Decrypts a passphrase-mode container.</summary>
    public static DecryptionResult DecryptWithPassphrase(
        Stream input,
        Stream output,
        string passphrase,
        VerificationPolicy? policy = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(passphrase);

        var header = FileHeader.Read(input);
        if (header.Mode != ShroudFormat.ModePassphrase)
            throw new ShroudFormatException("This container is encrypted to a public key; supply a key file, not a passphrase.");

        var headerHash = header.ComputeHash();
        var fileKey = KeyDerivation.ForPassphrase(passphrase, header);

        try
        {
            return Open(input, output, fileKey, header, headerHash, recipient: null, policy);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fileKey);
        }
    }

    /// <summary>Reads just the header, for inspection. Requires no key.</summary>
    public static FileHeader ReadHeader(Stream input) => FileHeader.Read(input);

    private static void Seal(
        Stream plaintext,
        Stream output,
        byte[] fileKey,
        byte[] headerHash,
        int chunkSize,
        ShroudSecretKey? sender,
        ShroudPublicKey? recipient)
    {
        var summary = ChunkedAead.EncryptPayload(plaintext, output, fileKey, headerHash, chunkSize);

        if (sender is null)
            return;

        var trailer = ContainerSignature.BuildTrailer(sender, recipient, headerHash, summary.Hash, summary.Length);
        ChunkedAead.WriteSignatureTrailer(output, fileKey, headerHash, summary.NextChunkIndex, trailer);
    }

    private static DecryptionResult Open(
        Stream input,
        Stream output,
        byte[] fileKey,
        FileHeader header,
        byte[] headerHash,
        ShroudPublicKey? recipient,
        VerificationPolicy? policy)
    {
        var effective = policy ?? VerificationPolicy.Optional;

        // Check the policy against the header before doing any work: an attacker who strips a
        // signature must not be able to have the container silently accepted as unsigned.
        if (!header.IsSigned && (effective.RequireSignature || effective.ExpectedSender is not null))
            throw new ShroudSignatureException("Container is not signed, but a verified signature was required.");

        var payload = ChunkedAead.DecryptPayload(input, output, fileKey, headerHash, header.ChunkSize, header.IsSigned);

        if (!header.IsSigned)
            return new DecryptionResult(WasSigned: false, Sender: null, SenderWasExpected: false, header.IsArchive);

        var sender = ContainerSignature.VerifyTrailer(
            payload.SignatureTrailer!,
            recipient,
            effective.ExpectedSender,
            headerHash,
            payload.Hash,
            payload.Length);

        return new DecryptionResult(
            WasSigned: true,
            Sender: sender,
            SenderWasExpected: effective.ExpectedSender is not null,
            header.IsArchive);
    }

    private static void ValidateChunkSizeLog(byte chunkSizeLog)
    {
        if (chunkSizeLog < ShroudFormat.MinChunkSizeLog || chunkSizeLog > ShroudFormat.MaxChunkSizeLog)
        {
            throw new ArgumentOutOfRangeException(
                nameof(chunkSizeLog),
                $"Chunk size exponent must be between {ShroudFormat.MinChunkSizeLog} and {ShroudFormat.MaxChunkSizeLog}.");
        }
    }
}
