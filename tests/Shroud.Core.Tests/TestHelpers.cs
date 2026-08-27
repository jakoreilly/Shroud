using Shroud.Core;

namespace Shroud.Core.Tests;

internal static class Helpers
{
    /// <summary>4 KiB chunks, so multi-chunk paths are exercised without megabytes of test data.</summary>
    public const byte TinyChunk = ShroudFormat.MinChunkSizeLog;

    public const int TinyChunkSize = 1 << TinyChunk;

    /// <summary>On-disk size of one full 4 KiB chunk: prefix + ciphertext + tag.</summary>
    public const int FramedChunk = ShroudFormat.ChunkPrefixLength + TinyChunkSize + ShroudFormat.TagLength;

    public const int RecipientHeader = ShroudFormat.RecipientHeaderLength;

    public const int PassphraseHeader = ShroudFormat.PassphraseHeaderLength;

    public const string Passphrase = "correct horse battery staple";

    /// <summary>Deliberately cheap Argon2 costs: these tests exercise plumbing, not key stretching.</summary>
    public static Argon2Settings CheapArgon2 { get; } = new(Iterations: 1, MemoryKib: 64, Lanes: 1);

    public static byte[] EncryptTo(
        byte[] plaintext,
        ShroudPublicKey recipient,
        ShroudSecretKey? sender = null,
        byte chunkSizeLog = TinyChunk)
    {
        using var input = new MemoryStream(plaintext);
        using var output = new MemoryStream();
        ShroudFile.Encrypt(input, output, recipient, sender, chunkSizeLog);
        return output.ToArray();
    }

    public static byte[] DecryptWith(
        byte[] container,
        ShroudSecretKey secretKey,
        VerificationPolicy? policy = null)
    {
        using var input = new MemoryStream(container);
        using var output = new MemoryStream();
        ShroudFile.Decrypt(input, output, secretKey, policy);
        return output.ToArray();
    }

    public static (byte[] Plaintext, DecryptionResult Result) DecryptWithResult(
        byte[] container,
        ShroudSecretKey secretKey,
        VerificationPolicy? policy = null)
    {
        using var input = new MemoryStream(container);
        using var output = new MemoryStream();
        var result = ShroudFile.Decrypt(input, output, secretKey, policy);
        return (output.ToArray(), result);
    }

    public static byte[] EncryptWithPassphrase(
        byte[] plaintext,
        ShroudSecretKey? sender = null,
        byte chunkSizeLog = TinyChunk)
    {
        using var input = new MemoryStream(plaintext);
        using var output = new MemoryStream();
        ShroudFile.EncryptWithPassphrase(input, output, Passphrase, sender, CheapArgon2, chunkSizeLog);
        return output.ToArray();
    }

    public static byte[] DecryptWithPassphrase(
        byte[] container,
        string passphrase,
        VerificationPolicy? policy = null)
    {
        using var input = new MemoryStream(container);
        using var output = new MemoryStream();
        ShroudFile.DecryptWithPassphrase(input, output, passphrase, policy);
        return output.ToArray();
    }

    public static (byte[] Plaintext, DecryptionResult Result) DecryptWithPassphraseResult(
        byte[] container,
        VerificationPolicy? policy = null)
    {
        using var input = new MemoryStream(container);
        using var output = new MemoryStream();
        var result = ShroudFile.DecryptWithPassphrase(input, output, Passphrase, policy);
        return (output.ToArray(), result);
    }
}
