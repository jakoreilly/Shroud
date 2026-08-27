using Shroud.Core;

namespace Shroud.Core.Tests;

public class KeyTests
{
    [Fact]
    public void PublicKeyBlob_HasTheExpectedLength()
    {
        var blob = ShroudSecretKey.Generate().GetPublicKey().ToBlob();

        // ML-KEM-768 (1184) + X25519 (32) + ML-DSA-65 (1952).
        Assert.Equal(3168, blob.Length);
        Assert.Equal(ShroudFormat.PublicKeyBlobLength, blob.Length);
    }

    [Fact]
    public void SecretKeyBlob_HasTheExpectedLength()
    {
        var blob = ShroudSecretKey.Generate().ToBlob();

        // Three seeds: ML-KEM (64) + X25519 (32) + ML-DSA (32).
        Assert.Equal(128, blob.Length);
        Assert.Equal(ShroudFormat.SecretKeyBlobLength, blob.Length);
    }

    [Fact]
    public void SecretKeySurvivesAnArmourRoundTrip()
    {
        var original = ShroudSecretKey.Generate();

        var restored = ShroudSecretKey.Parse(original.ToArmoredString());

        Assert.Equal(original.ToBlob(), restored.ToBlob());
        Assert.Equal(original.GetPublicKey().ToBlob(), restored.GetPublicKey().ToBlob());
    }

    [Fact]
    public void PublicKeySurvivesAnArmourRoundTrip()
    {
        var original = ShroudSecretKey.Generate().GetPublicKey();

        Assert.Equal(original.ToBlob(), ShroudPublicKey.Parse(original.ToArmoredString()).ToBlob());
    }

    [Fact]
    public void RestoredSecretKeyStillDecryptsAndSigns()
    {
        var original = ShroudSecretKey.Generate();
        var restored = ShroudSecretKey.Parse(original.ToArmoredString());

        // Signed by the original, decrypted and verified with the restored key: both the KEM
        // seed and the ML-DSA seed have to survive the round trip.
        var container = Helpers.EncryptTo([1, 2, 3, 4, 5], original.GetPublicKey(), original);

        var (plaintext, result) = Helpers.DecryptWithResult(
            container,
            restored,
            VerificationPolicy.From(restored.GetPublicKey()));

        Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, plaintext);
        Assert.True(result.SenderWasExpected);
    }

    [Fact]
    public void KeyFilesMayCarryCommentLines()
    {
        var original = ShroudSecretKey.Generate();
        var text = "# a comment\n\n" + original.ToArmoredString() + "\n";

        Assert.Equal(original.ToBlob(), ShroudSecretKey.Parse(text).ToBlob());
    }

    [Fact]
    public void GeneratedKeysAreDistinct()
    {
        Assert.NotEqual(ShroudSecretKey.Generate().ToBlob(), ShroudSecretKey.Generate().ToBlob());
    }

    [Fact]
    public void FingerprintIsStableAndSixteenHexDigits()
    {
        var publicKey = ShroudSecretKey.Generate().GetPublicKey();

        Assert.Equal(16, publicKey.Fingerprint().Length);
        Assert.Equal(publicKey.Fingerprint(), ShroudPublicKey.Parse(publicKey.ToArmoredString()).Fingerprint());
    }

    [Fact]
    public void FingerprintCoversTheWholeIdentity()
    {
        var a = ShroudSecretKey.Generate().GetPublicKey();
        var b = ShroudSecretKey.Generate().GetPublicKey();

        Assert.NotEqual(a.Fingerprint(), b.Fingerprint());
    }

    [Fact]
    public void ParsingAPublicKeyAsASecretKey_IsRejected()
    {
        var armored = ShroudSecretKey.Generate().GetPublicKey().ToArmoredString();

        var ex = Assert.Throws<ShroudFormatException>(() => ShroudSecretKey.Parse(armored));
        Assert.Contains("expected prefix", ex.Message);
    }

    [Fact]
    public void ParsingASecretKeyAsAPublicKey_IsRejected()
    {
        var armored = ShroudSecretKey.Generate().ToArmoredString();

        Assert.Throws<ShroudFormatException>(() => ShroudPublicKey.Parse(armored));
    }

    [Fact]
    public void EmptyKeyFile_IsRejected()
    {
        Assert.Throws<ShroudFormatException>(() => ShroudSecretKey.Parse("   \n # only a comment \n"));
    }

    [Fact]
    public void MalformedBase64_IsRejected()
    {
        var ex = Assert.Throws<ShroudFormatException>(() => ShroudSecretKey.Parse("shroud-secret-key:v2:!!!not base64!!!"));
        Assert.Contains("malformed base64", ex.Message);
    }

    [Fact]
    public void WrongLengthBlob_IsRejected()
    {
        var armored = "shroud-secret-key:v2:" + Convert.ToBase64String(new byte[10]);

        var ex = Assert.Throws<ShroudFormatException>(() => ShroudSecretKey.Parse(armored));
        Assert.Contains("must be 128 bytes", ex.Message);
    }

    [Fact]
    public void ProtectedKeyFile_RoundTripsUnderItsPassphrase()
    {
        var original = ShroudSecretKey.Generate();
        var armored = Protect(original);

        Assert.True(ShroudSecretKey.IsPassphraseProtected(armored));

        var restored = ShroudSecretKey.Parse(armored, () => Helpers.Passphrase);

        Assert.Equal(original.ToBlob(), restored.ToBlob());
    }

    [Fact]
    public void ProtectedKeyFile_IsNotReadableAsAPlainKeyFile()
    {
        var armored = Protect(ShroudSecretKey.Generate());

        // The envelope carries its own label, so a caller that never passes a passphrase gets a
        // clear error rather than a length or base64 failure.
        var ex = Assert.Throws<ShroudFormatException>(() => ShroudSecretKey.Parse(armored));
        Assert.Contains("expected prefix", ex.Message);
    }

    [Fact]
    public void ProtectedKeyFile_RejectsTheWrongPassphrase()
    {
        var armored = Protect(ShroudSecretKey.Generate());

        var ex = Assert.Throws<ShroudFormatException>(() => ShroudSecretKey.Parse(armored, () => "not the passphrase"));
        Assert.Contains("Wrong passphrase", ex.Message);
    }

    [Fact]
    public void UnprotectedKeyFile_NeverAsksForAPassphrase()
    {
        var original = ShroudSecretKey.Generate();
        bool asked = false;

        var restored = ShroudSecretKey.Parse(original.ToArmoredString(), () =>
        {
            asked = true;
            return Helpers.Passphrase;
        });

        Assert.False(asked);
        Assert.False(ShroudSecretKey.IsPassphraseProtected(original.ToArmoredString()));
        Assert.Equal(original.ToBlob(), restored.ToBlob());
    }

    [Fact]
    public void ProtectedKeyFile_ProducesDifferentCiphertextEachTime()
    {
        var original = ShroudSecretKey.Generate();

        Assert.NotEqual(Protect(original), Protect(original));
    }

    [Fact]
    public void EditingAProtectedKeyFile_IsDetected()
    {
        var original = ShroudSecretKey.Generate();

        // Flip a bit in the Argon2 salt. It is covered by the envelope's associated data, so the
        // tag fails rather than the unwrap silently producing garbage.
        var armored = MutateEnvelope(Protect(original), envelope => envelope[2] ^= 0x01);

        var ex = Assert.Throws<ShroudFormatException>(() => ShroudSecretKey.Parse(armored, () => Helpers.Passphrase));
        Assert.Contains("Wrong passphrase for this key file, or the file was modified", ex.Message);
    }

    [Fact]
    public void DowngradingAProtectedKeyFileCosts_IsRejected()
    {
        var original = ShroudSecretKey.Generate();

        // Zero the iteration count. The costs are range-checked before any derivation, so this
        // is refused outright instead of being honoured.
        var armored = MutateEnvelope(Protect(original), envelope =>
        {
            for (int i = 0; i < 4; i++)
                envelope[1 + ShroudFormat.SaltLength + i] = 0;
        });

        var ex = Assert.Throws<ShroudFormatException>(() => ShroudSecretKey.Parse(armored, () => Helpers.Passphrase));
        Assert.Contains("iterations out of range", ex.Message);
    }

    [Fact]
    public void TruncatedProtectedKeyFile_IsRejected()
    {
        var armored = MutateEnvelope(Protect(ShroudSecretKey.Generate()), _ => { }, trimBytes: 4);

        var ex = Assert.Throws<ShroudFormatException>(() => ShroudSecretKey.Parse(armored, () => Helpers.Passphrase));
        Assert.Contains("wrong length", ex.Message);
    }

    [Fact]
    public void ProtectingWithAnEmptyPassphrase_IsRejected()
    {
        var original = ShroudSecretKey.Generate();

        Assert.Throws<ArgumentException>(() => original.ToArmoredString(string.Empty, Helpers.CheapArgon2));
    }

    /// <summary>Wraps a key with deliberately cheap Argon2 costs: these tests exercise plumbing.</summary>
    private static string Protect(ShroudSecretKey key) =>
        key.ToArmoredString(Helpers.Passphrase, Helpers.CheapArgon2);

    private static string MutateEnvelope(string armored, Action<byte[]> mutate, int trimBytes = 0)
    {
        var envelope = Convert.FromBase64String(armored[EncryptedKeyFile.Label.Length..]);
        mutate(envelope);

        return EncryptedKeyFile.Label + Convert.ToBase64String(envelope.AsSpan(0, envelope.Length - trimBytes));
    }
}
