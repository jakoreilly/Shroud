using System.Security.Cryptography;
using Shroud.Core;

namespace Shroud.Core.Tests;

public class RoundTripTests
{
    [Theory]
    [InlineData(0)]          // empty file
    [InlineData(1)]
    [InlineData(4095)]       // just under one chunk
    [InlineData(4096)]       // exactly one chunk: the final-chunk boundary
    [InlineData(4097)]       // one chunk plus a byte
    [InlineData(8192)]       // exactly two chunks
    [InlineData(20000)]      // several chunks, ragged tail
    public void RecipientMode_RoundTripsExactly(int size)
    {
        var secretKey = ShroudSecretKey.Generate();
        var plaintext = RandomNumberGenerator.GetBytes(size);

        var container = Helpers.EncryptTo(plaintext, secretKey.GetPublicKey());
        var recovered = Helpers.DecryptWith(container, secretKey);

        Assert.Equal(plaintext, recovered);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(4096)]
    [InlineData(20000)]
    public void PassphraseMode_RoundTripsExactly(int size)
    {
        var plaintext = RandomNumberGenerator.GetBytes(size);

        var container = Helpers.EncryptWithPassphrase(plaintext);
        var recovered = Helpers.DecryptWithPassphrase(container, Helpers.Passphrase);

        Assert.Equal(plaintext, recovered);
    }

    [Fact]
    public void UnsignedContainer_ReportsThatNothingWasEstablished()
    {
        var secretKey = ShroudSecretKey.Generate();
        var container = Helpers.EncryptTo([1, 2, 3], secretKey.GetPublicKey());

        var (_, result) = Helpers.DecryptWithResult(container, secretKey);

        Assert.False(result.WasSigned);
        Assert.Null(result.Sender);
        Assert.False(result.SenderWasExpected);
    }

    [Fact]
    public void RecipientMode_ProducesDifferentCiphertextEachTime()
    {
        var publicKey = ShroudSecretKey.Generate().GetPublicKey();
        var plaintext = new byte[1024];

        var first = Helpers.EncryptTo(plaintext, publicKey);
        var second = Helpers.EncryptTo(plaintext, publicKey);

        Assert.NotEqual(first, second);
    }

    [Fact]
    public void PassphraseMode_ProducesDifferentCiphertextEachTime()
    {
        var plaintext = new byte[1024];

        Assert.NotEqual(Helpers.EncryptWithPassphrase(plaintext), Helpers.EncryptWithPassphrase(plaintext));
    }

    [Fact]
    public void WrongSecretKey_FailsAuthentication()
    {
        var container = Helpers.EncryptTo(new byte[512], ShroudSecretKey.Generate().GetPublicKey());

        // ML-KEM rejects implicitly, so this must surface as an AEAD failure, not a KEM error.
        var ex = Assert.Throws<ShroudFormatException>(() => Helpers.DecryptWith(container, ShroudSecretKey.Generate()));
        Assert.Contains("first chunk", ex.Message);
    }

    [Fact]
    public void WrongPassphrase_FailsAuthentication()
    {
        var container = Helpers.EncryptWithPassphrase(new byte[512]);

        var ex = Assert.Throws<ShroudFormatException>(
            () => Helpers.DecryptWithPassphrase(container, "not the passphrase"));
        Assert.Contains("first chunk", ex.Message);
    }

    [Fact]
    public void PassphraseContainer_RejectsKeyFileDecryption()
    {
        var container = Helpers.EncryptWithPassphrase(new byte[64]);

        var ex = Assert.Throws<ShroudFormatException>(() => Helpers.DecryptWith(container, ShroudSecretKey.Generate()));
        Assert.Contains("passphrase-encrypted", ex.Message);
    }

    [Fact]
    public void RecipientContainer_RejectsPassphraseDecryption()
    {
        var container = Helpers.EncryptTo(new byte[64], ShroudSecretKey.Generate().GetPublicKey());

        var ex = Assert.Throws<ShroudFormatException>(
            () => Helpers.DecryptWithPassphrase(container, Helpers.Passphrase));
        Assert.Contains("public key", ex.Message);
    }

    [Fact]
    public void ChunkSizeIsRecordedAndHonoured()
    {
        var secretKey = ShroudSecretKey.Generate();
        var plaintext = RandomNumberGenerator.GetBytes(10000);

        // Encrypted with 4 KiB chunks; the decryptor must learn that from the header alone.
        var container = Helpers.EncryptTo(plaintext, secretKey.GetPublicKey(), chunkSizeLog: Helpers.TinyChunk);

        using var input = new MemoryStream(container);
        Assert.Equal(4096, ShroudFile.ReadHeader(input).ChunkSize);

        Assert.Equal(plaintext, Helpers.DecryptWith(container, secretKey));
    }

    [Fact]
    public void ContainersWithDifferentChunkSizesBothRoundTrip()
    {
        var secretKey = ShroudSecretKey.Generate();
        var plaintext = RandomNumberGenerator.GetBytes(9000);

        foreach (byte log in new byte[] { 12, 13, 20 })
        {
            var container = Helpers.EncryptTo(plaintext, secretKey.GetPublicKey(), chunkSizeLog: log);
            Assert.Equal(plaintext, Helpers.DecryptWith(container, secretKey));
        }
    }

    [Theory]
    [InlineData(11)]
    [InlineData(27)]
    public void OutOfRangeChunkSize_IsRejected(byte log)
    {
        var publicKey = ShroudSecretKey.Generate().GetPublicKey();

        Assert.Throws<ArgumentOutOfRangeException>(
            () => Helpers.EncryptTo(new byte[16], publicKey, chunkSizeLog: log));
    }

    [Fact]
    public void EmptyPassphrase_IsRejected()
    {
        using var input = new MemoryStream();
        using var output = new MemoryStream();

        Assert.Throws<ArgumentException>(() => ShroudFile.EncryptWithPassphrase(input, output, string.Empty));
    }

    [Fact]
    public void HeaderReportsWhetherTheContainerIsSigned()
    {
        var secretKey = ShroudSecretKey.Generate();
        var publicKey = secretKey.GetPublicKey();

        using var unsigned = new MemoryStream(Helpers.EncryptTo([1, 2, 3], publicKey));
        using var signed = new MemoryStream(Helpers.EncryptTo([1, 2, 3], publicKey, secretKey));

        Assert.False(ShroudFile.ReadHeader(unsigned).IsSigned);
        Assert.True(ShroudFile.ReadHeader(signed).IsSigned);
    }

    [Fact]
    public void ArchiveFlag_RoundTripsAndIsReportedBothWays()
    {
        var secretKey = ShroudSecretKey.Generate();
        var plaintext = RandomNumberGenerator.GetBytes(5000);

        using var input = new MemoryStream(plaintext);
        using var container = new MemoryStream();
        ShroudFile.Encrypt(input, container, secretKey.GetPublicKey(), archive: true);

        container.Position = 0;
        Assert.True(ShroudFile.ReadHeader(container).IsArchive);

        container.Position = 0;
        using var output = new MemoryStream();
        var result = ShroudFile.Decrypt(container, output, secretKey);

        Assert.True(result.IsArchive);
        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public void ArchiveAndSignatureFlagsCoexist()
    {
        var alice = ShroudSecretKey.Generate();
        var bob = ShroudSecretKey.Generate();

        using var input = new MemoryStream([1, 2, 3]);
        using var container = new MemoryStream();
        ShroudFile.EncryptWithPassphrase(input, container, Helpers.Passphrase, alice, Helpers.CheapArgon2, archive: true);

        container.Position = 0;
        using var output = new MemoryStream();
        var result = ShroudFile.DecryptWithPassphrase(
            container, output, Helpers.Passphrase, VerificationPolicy.From(alice.GetPublicKey()));

        Assert.True(result.IsArchive);
        Assert.True(result.SenderWasExpected);
        Assert.False(bob.GetPublicKey().ToBlob().AsSpan().SequenceEqual(result.Sender!.ToBlob()));
    }

    [Fact]
    public void PlainContainer_IsNotReportedAsAnArchive()
    {
        var secretKey = ShroudSecretKey.Generate();
        var container = Helpers.EncryptTo([1, 2, 3], secretKey.GetPublicKey());

        var (_, result) = Helpers.DecryptWithResult(container, secretKey);

        Assert.False(result.IsArchive);
    }

    /// <summary>
    /// Pins the on-the-wire overhead. If a header or framing field changes size, this fails before
    /// the format drifts away from FORMAT.md.
    /// </summary>
    [Fact]
    public void ContainerSize_MatchesTheDocumentedOverhead()
    {
        var secretKey = ShroudSecretKey.Generate();
        var publicKey = secretKey.GetPublicKey();

        int framedEmptyChunk = ShroudFormat.ChunkPrefixLength + ShroudFormat.TagLength;
        int framedTrailer = ShroudFormat.ChunkPrefixLength + ShroudFormat.SignatureTrailerLength + ShroudFormat.TagLength;

        Assert.Equal(1129, ShroudFormat.RecipientHeaderLength);
        Assert.Equal(37, ShroudFormat.PassphraseHeaderLength);
        Assert.Equal(6477, ShroudFormat.SignatureTrailerLength);

        Assert.Equal(
            ShroudFormat.RecipientHeaderLength + framedEmptyChunk,
            Helpers.EncryptTo([], publicKey).Length);

        Assert.Equal(
            ShroudFormat.RecipientHeaderLength + framedEmptyChunk + framedTrailer,
            Helpers.EncryptTo([], publicKey, secretKey).Length);

        Assert.Equal(
            ShroudFormat.PassphraseHeaderLength + framedEmptyChunk,
            Helpers.EncryptWithPassphrase([]).Length);

        // Three full 4 KiB chunks plus a 712-byte tail.
        Assert.Equal(
            ShroudFormat.RecipientHeaderLength + (3 * Helpers.FramedChunk)
                + ShroudFormat.ChunkPrefixLength + 712 + ShroudFormat.TagLength,
            Helpers.EncryptTo(new byte[13000], publicKey).Length);
    }
}
