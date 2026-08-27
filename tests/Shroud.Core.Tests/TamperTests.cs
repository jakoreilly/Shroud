using System.Security.Cryptography;
using Shroud.Core;

namespace Shroud.Core.Tests;

/// <summary>
/// These are the tests that justify the format's design: every one of them fails loudly
/// on a naive chunked-AEAD implementation.
/// </summary>
public class TamperTests
{
    private const int HeaderLength = Helpers.RecipientHeader;

    private const int FramedChunk = Helpers.FramedChunk;

    /// <summary>Offset of the kind byte in the first chunk.</summary>
    private const int FirstChunkKind = HeaderLength;

    /// <summary>Offset of the declared plaintext length in the first chunk.</summary>
    private const int FirstChunkLength = HeaderLength + 1;

    [Fact]
    public void FlippingAByteInThePayload_FailsAuthentication()
    {
        var secretKey = ShroudSecretKey.Generate();
        var container = Helpers.EncryptTo(RandomNumberGenerator.GetBytes(9000), secretKey.GetPublicKey());

        container[HeaderLength + ShroudFormat.ChunkPrefixLength + 10] ^= 0x01;

        Assert.Throws<ShroudFormatException>(() => Helpers.DecryptWith(container, secretKey));
    }

    [Fact]
    public void FlippingAByteInTheHeader_FailsAuthentication()
    {
        var secretKey = ShroudSecretKey.Generate();
        var container = Helpers.EncryptTo(RandomNumberGenerator.GetBytes(1000), secretKey.GetPublicKey());

        // Inside the ML-KEM ciphertext: the header hash changes, so the file key changes.
        container[20] ^= 0x01;

        Assert.Throws<ShroudFormatException>(() => Helpers.DecryptWith(container, secretKey));
    }

    [Fact]
    public void ChangingTheRecordedChunkSize_FailsAuthentication()
    {
        var secretKey = ShroudSecretKey.Generate();
        var container = Helpers.EncryptTo(RandomNumberGenerator.GetBytes(9000), secretKey.GetPublicKey());

        container[7] = 13; // chunkSizeLog 12 -> 13

        Assert.Throws<ShroudFormatException>(() => Helpers.DecryptWith(container, secretKey));
    }

    [Fact]
    public void SettingAnUnknownHeaderFlag_IsRejected()
    {
        var secretKey = ShroudSecretKey.Generate();
        var container = Helpers.EncryptTo(new byte[64], secretKey.GetPublicKey());

        container[8] = 0x80;

        // Unknown flags are refused rather than ignored: an unknown flag could mean the container
        // carries something this build would silently skip.
        var ex = Assert.Throws<ShroudFormatException>(() => Helpers.DecryptWith(container, secretKey));
        Assert.Contains("unknown header flags", ex.Message);
    }

    [Fact]
    public void SettingTheArchiveFlag_FailsAuthentication()
    {
        var secretKey = ShroudSecretKey.Generate();
        var container = Helpers.EncryptTo(RandomNumberGenerator.GetBytes(1000), secretKey.GetPublicKey());

        // Claiming a plain file is an archive would talk a decryptor into unpacking it. The flag
        // is in the header, and the header hash keys every chunk, so it cannot be flipped.
        container[8] |= ShroudFormat.FlagArchive;

        var ex = Assert.Throws<ShroudFormatException>(() => Helpers.DecryptWith(container, secretKey));
        Assert.Contains("Authentication failed", ex.Message);
    }

    [Fact]
    public void TruncatingTrailingChunks_IsDetected()
    {
        var secretKey = ShroudSecretKey.Generate();

        // Three full chunks plus a tail.
        var container = Helpers.EncryptTo(RandomNumberGenerator.GetBytes(13000), secretKey.GetPublicKey());

        // Drop the final partial chunk entirely, leaving a container of whole chunks.
        var truncated = container[..(HeaderLength + (3 * FramedChunk))];

        // Every surviving chunk was authenticated as non-final, so nothing claims to end the payload.
        var ex = Assert.Throws<ShroudFormatException>(() => Helpers.DecryptWith(truncated, secretKey));
        Assert.Contains("no chunk was marked as the end of the payload", ex.Message);
    }

    [Fact]
    public void TruncatingMidChunk_IsDetected()
    {
        var secretKey = ShroudSecretKey.Generate();
        var container = Helpers.EncryptTo(RandomNumberGenerator.GetBytes(13000), secretKey.GetPublicKey());

        var ex = Assert.Throws<ShroudFormatException>(
            () => Helpers.DecryptWith(container[..(container.Length - 20)], secretKey));
        Assert.Contains("truncated inside chunk", ex.Message);
    }

    [Fact]
    public void AppendingAChunkAfterTheFinalChunk_IsDetected()
    {
        var secretKey = ShroudSecretKey.Generate();
        var container = Helpers.EncryptTo(RandomNumberGenerator.GetBytes(5000), secretKey.GetPublicKey());

        // Well-formed framing for one more full payload chunk: it parses, but the payload has
        // already been marked complete.
        var extended = container.Concat(new byte[FramedChunk]).ToArray();
        extended[container.Length] = ShroudFormat.ChunkPayload;
        extended[container.Length + 4] = 0x10; // length 4096, big-endian

        var ex = Assert.Throws<ShroudFormatException>(() => Helpers.DecryptWith(extended, secretKey));
        Assert.Contains("already marked complete", ex.Message);
    }

    [Fact]
    public void AppendingGarbageAfterTheFinalChunk_IsDetected()
    {
        var secretKey = ShroudSecretKey.Generate();
        var container = Helpers.EncryptTo(RandomNumberGenerator.GetBytes(5000), secretKey.GetPublicKey());

        var extended = container.Concat(RandomNumberGenerator.GetBytes(64)).ToArray();

        Assert.Throws<ShroudFormatException>(() => Helpers.DecryptWith(extended, secretKey));
    }

    [Fact]
    public void ReorderingChunks_IsDetected()
    {
        var secretKey = ShroudSecretKey.Generate();

        // 13000 bytes = three full chunks (indices 0-2, all non-final) plus a final tail.
        // Swapping chunks 0 and 1 keeps both lengths and both kinds identical, so only the
        // authenticated chunk index can catch it.
        var container = Helpers.EncryptTo(RandomNumberGenerator.GetBytes(13000), secretKey.GetPublicKey());

        var swapped = container.ToArray();
        var first = container.AsSpan(HeaderLength, FramedChunk).ToArray();
        var second = container.AsSpan(HeaderLength + FramedChunk, FramedChunk).ToArray();
        second.CopyTo(swapped, HeaderLength);
        first.CopyTo(swapped, HeaderLength + FramedChunk);

        var ex = Assert.Throws<ShroudFormatException>(() => Helpers.DecryptWith(swapped, secretKey));
        Assert.Contains("Authentication failed", ex.Message);
    }

    [Fact]
    public void DuplicatingAChunk_IsDetected()
    {
        var secretKey = ShroudSecretKey.Generate();
        var container = Helpers.EncryptTo(RandomNumberGenerator.GetBytes(8192), secretKey.GetPublicKey());

        var duplicated = container[..(HeaderLength + FramedChunk)]
            .Concat(container.AsSpan(HeaderLength, FramedChunk).ToArray())
            .Concat(container.AsSpan(HeaderLength + FramedChunk).ToArray())
            .ToArray();

        var ex = Assert.Throws<ShroudFormatException>(() => Helpers.DecryptWith(duplicated, secretKey));
        Assert.Contains("Authentication failed", ex.Message);
    }

    [Fact]
    public void SplicingChunksBetweenTwoFiles_IsDetected()
    {
        var secretKey = ShroudSecretKey.Generate();
        var publicKey = secretKey.GetPublicKey();

        var a = Helpers.EncryptTo(RandomNumberGenerator.GetBytes(8192), publicKey);
        var b = Helpers.EncryptTo(RandomNumberGenerator.GetBytes(8192), publicKey);

        // Same recipient, same chunk size: only the per-file key and header hash differ.
        var spliced = a[..(HeaderLength + FramedChunk)]
            .Concat(b.AsSpan(HeaderLength + FramedChunk).ToArray())
            .ToArray();

        var ex = Assert.Throws<ShroudFormatException>(() => Helpers.DecryptWith(spliced, secretKey));
        Assert.Contains("Authentication failed", ex.Message);
    }

    [Fact]
    public void RelabellingTheFinalChunkAsNonFinal_IsRejected()
    {
        var secretKey = ShroudSecretKey.Generate();

        // One short final chunk, so its declared length cannot pass as a full chunk.
        var container = Helpers.EncryptTo(RandomNumberGenerator.GetBytes(100), secretKey.GetPublicKey());

        container[FirstChunkKind] = ShroudFormat.ChunkPayload;

        var ex = Assert.Throws<ShroudFormatException>(() => Helpers.DecryptWith(container, secretKey));
        Assert.Contains("must hold exactly", ex.Message);
    }

    [Fact]
    public void EditingAChunkDeclaredLength_FailsAuthentication()
    {
        var secretKey = ShroudSecretKey.Generate();
        var container = Helpers.EncryptTo(RandomNumberGenerator.GetBytes(100), secretKey.GetPublicKey());

        // 100 -> 50. The length is in the associated data, so the tag no longer matches.
        container[FirstChunkLength + 3] = 50;

        var ex = Assert.Throws<ShroudFormatException>(() => Helpers.DecryptWith(container, secretKey));
        Assert.Contains("Authentication failed", ex.Message);
    }

    [Fact]
    public void OverlongChunkLength_IsRejectedBeforeAllocating()
    {
        var secretKey = ShroudSecretKey.Generate();
        var container = Helpers.EncryptTo(RandomNumberGenerator.GetBytes(100), secretKey.GetPublicKey());

        // Claim 2 GiB in a 4 KiB-chunk container: refused at parse time, before anything is read.
        container[FirstChunkLength] = 0x7F;
        container[FirstChunkLength + 1] = 0xFF;
        container[FirstChunkLength + 2] = 0xFF;
        container[FirstChunkLength + 3] = 0xFF;

        var ex = Assert.Throws<ShroudFormatException>(() => Helpers.DecryptWith(container, secretKey));
        Assert.Contains("more than the 4096-byte chunk size", ex.Message);
    }

    [Fact]
    public void NegativeChunkLength_IsRejected()
    {
        var secretKey = ShroudSecretKey.Generate();
        var container = Helpers.EncryptTo(RandomNumberGenerator.GetBytes(100), secretKey.GetPublicKey());

        container[FirstChunkLength] = 0xFF;

        var ex = Assert.Throws<ShroudFormatException>(() => Helpers.DecryptWith(container, secretKey));
        Assert.Contains("negative length", ex.Message);
    }

    [Fact]
    public void UnknownChunkKind_IsRejected()
    {
        var secretKey = ShroudSecretKey.Generate();
        var container = Helpers.EncryptTo(RandomNumberGenerator.GetBytes(100), secretKey.GetPublicKey());

        container[FirstChunkKind] = 99;

        var ex = Assert.Throws<ShroudFormatException>(() => Helpers.DecryptWith(container, secretKey));
        Assert.Contains("unknown kind 99", ex.Message);
    }

    [Fact]
    public void SwappingTheArgon2SaltBetweenFiles_IsDetected()
    {
        var a = Helpers.EncryptWithPassphrase(RandomNumberGenerator.GetBytes(2000));
        var b = Helpers.EncryptWithPassphrase(RandomNumberGenerator.GetBytes(2000));

        var tampered = a.ToArray();
        b.AsSpan(ShroudFormat.HeaderPrologueLength, ShroudFormat.SaltLength)
            .CopyTo(tampered.AsSpan(ShroudFormat.HeaderPrologueLength));

        var ex = Assert.Throws<ShroudFormatException>(
            () => Helpers.DecryptWithPassphrase(tampered, Helpers.Passphrase));
        Assert.Contains("Authentication failed", ex.Message);
    }

    [Fact]
    public void EmptyInput_IsRejectedAsMalformed()
    {
        var ex = Assert.Throws<ShroudFormatException>(
            () => Helpers.DecryptWith([], ShroudSecretKey.Generate()));

        Assert.Contains("truncated inside the header", ex.Message);
    }

    [Fact]
    public void BadMagic_IsRejectedWithAClearMessage()
    {
        var junk = new byte[200];
        RandomNumberGenerator.Fill(junk);

        var ex = Assert.Throws<ShroudFormatException>(() => Helpers.DecryptWith(junk, ShroudSecretKey.Generate()));
        Assert.Contains("bad magic", ex.Message);
    }

    [Fact]
    public void HeaderWithNoChunks_IsRejected()
    {
        var secretKey = ShroudSecretKey.Generate();
        var container = Helpers.EncryptTo([], secretKey.GetPublicKey());

        // Even an empty payload emits one final chunk; strip it and the container is invalid.
        var ex = Assert.Throws<ShroudFormatException>(
            () => Helpers.DecryptWith(container[..HeaderLength], secretKey));

        Assert.Contains("no chunk was marked as the end of the payload", ex.Message);
    }

    [Fact]
    public void UnsupportedVersion_IsRejected()
    {
        var secretKey = ShroudSecretKey.Generate();
        var container = Helpers.EncryptTo(new byte[64], secretKey.GetPublicKey());

        container[4] = 99;

        var ex = Assert.Throws<ShroudFormatException>(() => Helpers.DecryptWith(container, secretKey));
        Assert.Contains("Unsupported container version", ex.Message);
    }

    [Fact]
    public void UnsupportedSuite_IsRejected()
    {
        var secretKey = ShroudSecretKey.Generate();
        var container = Helpers.EncryptTo(new byte[64], secretKey.GetPublicKey());

        container[6] = 99;

        var ex = Assert.Throws<ShroudFormatException>(() => Helpers.DecryptWith(container, secretKey));
        Assert.Contains("Unsupported cipher suite", ex.Message);
    }

    [Fact]
    public void UnknownMode_IsRejected()
    {
        var secretKey = ShroudSecretKey.Generate();
        var container = Helpers.EncryptTo(new byte[64], secretKey.GetPublicKey());

        container[5] = 9;

        var ex = Assert.Throws<ShroudFormatException>(() => Helpers.DecryptWith(container, secretKey));
        Assert.Contains("Unknown container mode", ex.Message);
    }

    [Fact]
    public void HostileArgon2Costs_AreRejectedBeforeAllocating()
    {
        var container = Helpers.EncryptWithPassphrase(new byte[64]);

        // Claim an absurd Argon2 memory cost: must be refused at parse time, not honoured.
        int memoryOffset = ShroudFormat.HeaderPrologueLength + ShroudFormat.SaltLength + 4;
        container[memoryOffset] = 0xFF;
        container[memoryOffset + 1] = 0xFF;
        container[memoryOffset + 2] = 0xFF;

        var ex = Assert.Throws<ShroudFormatException>(
            () => Helpers.DecryptWithPassphrase(container, Helpers.Passphrase));

        Assert.Contains("out of range", ex.Message);
    }
}
