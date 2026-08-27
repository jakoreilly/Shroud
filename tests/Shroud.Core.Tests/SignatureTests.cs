using System.Security.Cryptography;
using Shroud.Core;

namespace Shroud.Core.Tests;

/// <summary>
/// Signing is only worth having if the signature is bound to the container it came in, to the
/// plaintext it covers, and to the recipient it was addressed to. These tests hold each of those
/// bindings separately, so a regression in one cannot hide behind another.
/// </summary>
public class SignatureTests
{
    private static readonly int FramedTrailer =
        ShroudFormat.ChunkPrefixLength + ShroudFormat.SignatureTrailerLength + ShroudFormat.TagLength;

    // ---- container level -------------------------------------------------------------------

    [Theory]
    [InlineData(0)]
    [InlineData(100)]
    [InlineData(13000)]
    public void SignedContainer_RoundTripsAndVerifies(int size)
    {
        var alice = ShroudSecretKey.Generate();
        var bob = ShroudSecretKey.Generate();
        var plaintext = RandomNumberGenerator.GetBytes(size);

        var container = Helpers.EncryptTo(plaintext, bob.GetPublicKey(), alice);

        var (recovered, result) = Helpers.DecryptWithResult(
            container,
            bob,
            VerificationPolicy.From(alice.GetPublicKey()));

        Assert.Equal(plaintext, recovered);
        Assert.True(result.WasSigned);
        Assert.True(result.SenderWasExpected);
        Assert.Equal(alice.GetPublicKey().Fingerprint(), result.SenderFingerprint);
    }

    [Fact]
    public void SignedPassphraseContainer_RoundTripsAndVerifies()
    {
        var alice = ShroudSecretKey.Generate();
        var plaintext = RandomNumberGenerator.GetBytes(9000);

        var container = Helpers.EncryptWithPassphrase(plaintext, alice);

        var (recovered, result) = Helpers.DecryptWithPassphraseResult(
            container,
            VerificationPolicy.From(alice.GetPublicKey()));

        Assert.Equal(plaintext, recovered);
        Assert.True(result.SenderWasExpected);
        Assert.Equal(alice.GetPublicKey().Fingerprint(), result.SenderFingerprint);
    }

    [Fact]
    public void WrongExpectedSender_IsRejected()
    {
        var alice = ShroudSecretKey.Generate();
        var mallory = ShroudSecretKey.Generate();
        var bob = ShroudSecretKey.Generate();

        var container = Helpers.EncryptTo(new byte[512], bob.GetPublicKey(), alice);

        var ex = Assert.Throws<ShroudSignatureException>(
            () => Helpers.DecryptWith(container, bob, VerificationPolicy.From(mallory.GetPublicKey())));

        Assert.Contains("was expected", ex.Message);
        Assert.Contains(alice.GetPublicKey().Fingerprint(), ex.Message);
    }

    [Fact]
    public void UnsignedContainer_UnderRequiredPolicy_IsRejected()
    {
        var bob = ShroudSecretKey.Generate();
        var container = Helpers.EncryptTo(new byte[512], bob.GetPublicKey());

        var ex = Assert.Throws<ShroudSignatureException>(
            () => Helpers.DecryptWith(container, bob, VerificationPolicy.Required));

        Assert.Contains("not signed", ex.Message);
    }

    [Fact]
    public void UnsignedContainer_WithAnExpectedSender_IsRejected()
    {
        var alice = ShroudSecretKey.Generate();
        var bob = ShroudSecretKey.Generate();
        var container = Helpers.EncryptTo(new byte[512], bob.GetPublicKey());

        Assert.Throws<ShroudSignatureException>(
            () => Helpers.DecryptWith(container, bob, VerificationPolicy.From(alice.GetPublicKey())));
    }

    [Fact]
    public void UnsignedPassphraseContainer_UnderRequiredPolicy_IsRejected()
    {
        var container = Helpers.EncryptWithPassphrase(new byte[512]);

        Assert.Throws<ShroudSignatureException>(
            () => Helpers.DecryptWithPassphraseResult(container, VerificationPolicy.Required));
    }

    [Fact]
    public void RequiredPolicy_IsCheckedBeforeAnyPlaintextIsWritten()
    {
        var bob = ShroudSecretKey.Generate();
        var container = Helpers.EncryptTo(RandomNumberGenerator.GetBytes(13000), bob.GetPublicKey());

        using var input = new MemoryStream(container);
        using var output = new MemoryStream();

        Assert.Throws<ShroudSignatureException>(
            () => ShroudFile.Decrypt(input, output, bob, VerificationPolicy.Required));

        // Refusing an unsigned container must not first hand the caller its contents.
        Assert.Equal(0, output.Length);
    }

    [Fact]
    public void SignedContainer_UnderOptionalPolicy_ReportsAnUncheckedIdentity()
    {
        var alice = ShroudSecretKey.Generate();
        var bob = ShroudSecretKey.Generate();

        var container = Helpers.EncryptTo(new byte[512], bob.GetPublicKey(), alice);
        var (_, result) = Helpers.DecryptWithResult(container, bob);

        // The signature verifies, but nobody said whose signature to expect -- anyone can generate
        // a key and sign with it, so this is not evidence of origin.
        Assert.True(result.WasSigned);
        Assert.False(result.SenderWasExpected);
        Assert.Equal(alice.GetPublicKey().Fingerprint(), result.SenderFingerprint);
    }

    [Fact]
    public void SenderIdentityIsNotVisibleInTheContainer()
    {
        var alice = ShroudSecretKey.Generate();
        var bob = ShroudSecretKey.Generate();

        var container = Helpers.EncryptTo(new byte[512], bob.GetPublicKey(), alice);

        // The trailer lives inside the encrypted region, so the sending identity is not in the
        // clear. That is a privacy property of the format, not an accident.
        Assert.Equal(-1, container.AsSpan().IndexOf(alice.GetPublicKey().ToBlob().AsSpan()));
    }

    [Fact]
    public void SignedContainerCostsExactlyOneTrailerChunk()
    {
        var alice = ShroudSecretKey.Generate();
        var bob = ShroudSecretKey.Generate();
        var plaintext = RandomNumberGenerator.GetBytes(9000);

        var unsigned = Helpers.EncryptTo(plaintext, bob.GetPublicKey());
        var signed = Helpers.EncryptTo(plaintext, bob.GetPublicKey(), alice);

        Assert.Equal(unsigned.Length + FramedTrailer, signed.Length);
    }

    [Fact]
    public void StrippingTheSignature_IsDetected()
    {
        var alice = ShroudSecretKey.Generate();
        var bob = ShroudSecretKey.Generate();

        var container = Helpers.EncryptTo(new byte[512], bob.GetPublicKey(), alice);

        // Clear the signed flag and drop the trailer, as an attacker would to pass a signed
        // container off as an unsigned one. The flag is in the header, and the header hash keys
        // every chunk, so the payload no longer authenticates at all.
        var stripped = container[..^FramedTrailer];
        stripped[8] = 0;

        var ex = Assert.Throws<ShroudFormatException>(() => Helpers.DecryptWith(stripped, bob));
        Assert.Contains("Authentication failed", ex.Message);
    }

    [Fact]
    public void RemovingOnlyTheTrailer_IsDetected()
    {
        var alice = ShroudSecretKey.Generate();
        var bob = ShroudSecretKey.Generate();

        var container = Helpers.EncryptTo(new byte[512], bob.GetPublicKey(), alice);

        var ex = Assert.Throws<ShroudFormatException>(
            () => Helpers.DecryptWith(container[..^FramedTrailer], bob));

        Assert.Contains("signature trailer is missing", ex.Message);
    }

    [Fact]
    public void FlippingAByteInTheTrailer_FailsAuthentication()
    {
        var alice = ShroudSecretKey.Generate();
        var bob = ShroudSecretKey.Generate();

        var container = Helpers.EncryptTo(new byte[512], bob.GetPublicKey(), alice);
        container[^100] ^= 0x01;

        var ex = Assert.Throws<ShroudFormatException>(() => Helpers.DecryptWith(container, bob));
        Assert.Contains("Authentication failed", ex.Message);
    }

    [Fact]
    public void LiftingATrailerOntoAnotherContainer_IsDetected()
    {
        var alice = ShroudSecretKey.Generate();
        var bob = ShroudSecretKey.Generate();

        // Same sender, same recipient, same size: only the per-file key differs.
        var a = Helpers.EncryptTo(RandomNumberGenerator.GetBytes(512), bob.GetPublicKey(), alice);
        var b = Helpers.EncryptTo(RandomNumberGenerator.GetBytes(512), bob.GetPublicKey(), alice);

        var spliced = a[..^FramedTrailer].Concat(b.AsSpan(b.Length - FramedTrailer).ToArray()).ToArray();

        var ex = Assert.Throws<ShroudFormatException>(() => Helpers.DecryptWith(spliced, bob));
        Assert.Contains("Authentication failed", ex.Message);
    }

    [Fact]
    public void UndeclaredTrailer_IsRejected()
    {
        var alice = ShroudSecretKey.Generate();

        // A correctly sealed trailer appended to a container whose header says it is unsigned.
        // The chunk itself authenticates, so only the kind/flag cross-check catches it.
        var container = Helpers.EncryptWithPassphrase([]);

        using var input = new MemoryStream(container);
        var header = ShroudFile.ReadHeader(input);
        var headerHash = header.ComputeHash();
        var fileKey = KeyDerivation.ForPassphrase(Helpers.Passphrase, header);

        var trailer = ContainerSignature.BuildTrailer(
            alice,
            recipient: null,
            headerHash,
            SHA256.HashData(Array.Empty<byte>()),
            plaintextLength: 0);

        using var forged = new MemoryStream();
        forged.Write(container);
        ChunkedAead.WriteSignatureTrailer(forged, fileKey, headerHash, index: 1, trailer);

        var ex = Assert.Throws<ShroudFormatException>(
            () => Helpers.DecryptWithPassphrase(forged.ToArray(), Helpers.Passphrase));

        Assert.Contains("does not declare one", ex.Message);
    }

    // ---- what the signature covers ---------------------------------------------------------

    [Fact]
    public void Trailer_VerifiesAndReturnsTheSender()
    {
        var alice = ShroudSecretKey.Generate();
        var fixture = new TrailerFixture(alice);

        var sender = fixture.Verify();

        Assert.Equal(alice.GetPublicKey().Fingerprint(), sender.Fingerprint());
        Assert.Equal(alice.GetPublicKey().ToBlob(), sender.ToBlob());
    }

    /// <summary>
    /// The Davis attack on naive sign-then-encrypt: without the recipient in the signed message,
    /// Bob could re-encrypt what Alice sent him to Carol, and Carol would read a valid Alice
    /// signature on a message Alice never sent her.
    /// </summary>
    [Fact]
    public void Trailer_IsBoundToTheRecipient()
    {
        var fixture = new TrailerFixture(ShroudSecretKey.Generate());
        var carol = ShroudSecretKey.Generate().GetPublicKey();

        Assert.Throws<ShroudSignatureException>(() => fixture.Verify(recipient: carol));
    }

    [Fact]
    public void Trailer_IsBoundToTheHeader()
    {
        var fixture = new TrailerFixture(ShroudSecretKey.Generate());

        Assert.Throws<ShroudSignatureException>(
            () => fixture.Verify(headerHash: RandomNumberGenerator.GetBytes(ShroudFormat.HashLength)));
    }

    [Fact]
    public void Trailer_IsBoundToThePlaintext()
    {
        var fixture = new TrailerFixture(ShroudSecretKey.Generate());

        Assert.Throws<ShroudSignatureException>(
            () => fixture.Verify(plaintextHash: RandomNumberGenerator.GetBytes(ShroudFormat.HashLength)));
    }

    [Fact]
    public void Trailer_IsBoundToThePlaintextLength()
    {
        var fixture = new TrailerFixture(ShroudSecretKey.Generate());

        Assert.Throws<ShroudSignatureException>(() => fixture.Verify(plaintextLength: TrailerFixture.Length + 1));
    }

    [Fact]
    public void PassphraseAndRecipientTrailersAreNotInterchangeable()
    {
        var alice = ShroudSecretKey.Generate();
        var bob = ShroudSecretKey.Generate().GetPublicKey();
        var headerHash = RandomNumberGenerator.GetBytes(ShroudFormat.HashLength);
        var plaintextHash = RandomNumberGenerator.GetBytes(ShroudFormat.HashLength);

        // Passphrase mode signs an empty recipient slot rather than omitting the field, so a
        // trailer cannot be moved between the two modes.
        var passphraseTrailer = ContainerSignature.BuildTrailer(alice, null, headerHash, plaintextHash, 10);
        var recipientTrailer = ContainerSignature.BuildTrailer(alice, bob, headerHash, plaintextHash, 10);

        Assert.Throws<ShroudSignatureException>(
            () => ContainerSignature.VerifyTrailer(passphraseTrailer, bob, null, headerHash, plaintextHash, 10));

        Assert.Throws<ShroudSignatureException>(
            () => ContainerSignature.VerifyTrailer(recipientTrailer, null, null, headerHash, plaintextHash, 10));
    }

    [Fact]
    public void SubstitutingTheSenderKey_IsDetected()
    {
        var fixture = new TrailerFixture(ShroudSecretKey.Generate());
        var mallory = ShroudSecretKey.Generate().GetPublicKey();

        // Swap in a different verification key. The sender blob is itself part of the signed
        // message, so the signature cannot be reinterpreted under a substituted identity.
        var forged = fixture.Trailer.ToArray();
        mallory.ToBlob().CopyTo(forged, 0);

        var ex = Assert.Throws<ShroudSignatureException>(() => fixture.Verify(trailer: forged));
        Assert.Contains("does not verify", ex.Message);
    }

    [Fact]
    public void WrongLengthTrailer_IsRejected()
    {
        var fixture = new TrailerFixture(ShroudSecretKey.Generate());

        var ex = Assert.Throws<ShroudSignatureException>(() => fixture.Verify(trailer: fixture.Trailer[..100]));
        Assert.Contains("wrong length", ex.Message);
    }

    [Fact]
    public void SigningIsHedged_SoTwoSignaturesOverTheSameMessageDiffer()
    {
        var alice = ShroudSecretKey.Generate();
        var bob = ShroudSecretKey.Generate().GetPublicKey();
        var headerHash = RandomNumberGenerator.GetBytes(ShroudFormat.HashLength);
        var plaintextHash = RandomNumberGenerator.GetBytes(ShroudFormat.HashLength);

        // FIPS 204 hedged signing mixes in fresh randomness; it is more robust against fault and
        // side-channel attacks than deterministic signing. Identical inputs, different signatures.
        var first = ContainerSignature.BuildTrailer(alice, bob, headerHash, plaintextHash, 10);
        var second = ContainerSignature.BuildTrailer(alice, bob, headerHash, plaintextHash, 10);

        Assert.NotEqual(first, second);

        // ...but the identity half of the trailer is the same key both times.
        Assert.Equal(
            first[..ShroudFormat.PublicKeyBlobLength],
            second[..ShroudFormat.PublicKeyBlobLength]);
    }

    /// <summary>One signed message and its trailer, with each argument overridable at verification time.</summary>
    private sealed class TrailerFixture
    {
        public const long Length = 4321;

        public TrailerFixture(ShroudSecretKey sender, ShroudPublicKey? recipient = null, byte[]? headerHash = null)
        {
            Sender = sender;
            Recipient = recipient ?? ShroudSecretKey.Generate().GetPublicKey();
            HeaderHash = headerHash ?? RandomNumberGenerator.GetBytes(ShroudFormat.HashLength);
            PlaintextHash = RandomNumberGenerator.GetBytes(ShroudFormat.HashLength);
            Trailer = ContainerSignature.BuildTrailer(Sender, Recipient, HeaderHash, PlaintextHash, Length);
        }

        public ShroudSecretKey Sender { get; }

        public ShroudPublicKey? Recipient { get; }

        public byte[] HeaderHash { get; }

        public byte[] PlaintextHash { get; }

        public byte[] Trailer { get; }

        public ShroudPublicKey Verify(
            byte[]? trailer = null,
            ShroudPublicKey? recipient = null,
            byte[]? headerHash = null,
            byte[]? plaintextHash = null,
            long? plaintextLength = null) =>
            ContainerSignature.VerifyTrailer(
                trailer ?? Trailer,
                recipient ?? Recipient,
                expectedSender: null,
                headerHash ?? HeaderHash,
                plaintextHash ?? PlaintextHash,
                plaintextLength ?? Length);
    }
}
