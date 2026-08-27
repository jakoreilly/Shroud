using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Shroud.Core;

/// <summary>
/// A SHROUD identity's public half: an ML-KEM-768 encapsulation key, an X25519 public key, and an
/// ML-DSA-65 verification key. One identity covers both receiving and signing.
/// </summary>
public sealed class ShroudPublicKey
{
    internal const string Label = "shroud-recipient:v2:";

    private const int X25519Offset = ShroudFormat.MlKemPublicKeyLength;

    private const int MlDsaOffset = X25519Offset + ShroudFormat.X25519KeyLength;

    private readonly byte[] _blob;

    // Decoding a lattice key is not free and one operation reads these more than once. Cached
    // rather than rebuilt per access; a key instance is driven by one operation at a time, so
    // plain fields are enough.
    private MLKemPublicKeyParameters? _mlKem;
    private MLDsaPublicKeyParameters? _mlDsa;

    internal ShroudPublicKey(byte[] blob)
    {
        if (blob.Length != ShroudFormat.PublicKeyBlobLength)
            throw new ShroudFormatException($"Public key must be {ShroudFormat.PublicKeyBlobLength} bytes, got {blob.Length}.");

        _blob = blob;
    }

    internal MLKemPublicKeyParameters MlKem =>
        _mlKem ??= MLKemPublicKeyParameters.FromEncoding(MLKemParameters.ml_kem_768, _blob[..X25519Offset]);

    internal X25519PublicKeyParameters X25519 => new(_blob, X25519Offset);

    internal MLDsaPublicKeyParameters MlDsa =>
        _mlDsa ??= MLDsaPublicKeyParameters.FromEncoding(MLDsaParameters.ml_dsa_65, _blob[MlDsaOffset..]);

    /// <summary>ML-KEM public key || X25519 public key || ML-DSA public key.</summary>
    public byte[] ToBlob() => (byte[])_blob.Clone();

    public static ShroudPublicKey FromBlob(byte[] blob) => new((byte[])blob.Clone());

    public string ToArmoredString() => Label + Convert.ToBase64String(_blob);

    public static ShroudPublicKey Parse(string text) =>
        new(KeyArmor.Decode(text, Label, "public key"));

    /// <summary>Short human-comparable fingerprint over the whole identity. Not used on the wire.</summary>
    public string Fingerprint() => Fingerprint(_blob);

    internal static string Fingerprint(byte[] blob) =>
        Convert.ToHexStringLower(SHA256.HashData(blob).AsSpan(0, 8));

    internal bool BlobEquals(byte[] other) =>
        CryptographicOperations.FixedTimeEquals(_blob, other);
}

/// <summary>
/// A SHROUD identity's secret half, stored as three seeds: the ML-KEM seed (64 bytes), the X25519
/// scalar (32 bytes), and the ML-DSA seed (32 bytes). 128 bytes covers the whole identity.
/// </summary>
public sealed class ShroudSecretKey
{
    internal const string Label = "shroud-secret-key:v2:";

    private const int X25519Offset = ShroudFormat.MlKemSeedLength;

    private const int MlDsaOffset = X25519Offset + ShroudFormat.X25519KeyLength;

    private readonly byte[] _blob;

    // Expanding a seed into a lattice key is expensive, and a single operation touches these
    // several times over -- GetPublicKey, then decapsulation or signing. Cached rather than
    // recomputed; a key instance is driven by one operation at a time, so plain fields are enough.
    private MLKemPrivateKeyParameters? _mlKem;
    private MLDsaPrivateKeyParameters? _mlDsa;

    internal ShroudSecretKey(byte[] blob)
    {
        if (blob.Length != ShroudFormat.SecretKeyBlobLength)
            throw new ShroudFormatException($"Secret key must be {ShroudFormat.SecretKeyBlobLength} bytes, got {blob.Length}.");

        _blob = blob;
    }

    internal MLKemPrivateKeyParameters MlKem =>
        _mlKem ??= MLKemPrivateKeyParameters.FromSeed(MLKemParameters.ml_kem_768, _blob[..X25519Offset]);

    internal X25519PrivateKeyParameters X25519 => new(_blob, X25519Offset);

    internal MLDsaPrivateKeyParameters MlDsa =>
        _mlDsa ??= MLDsaPrivateKeyParameters.FromSeed(MLDsaParameters.ml_dsa_65, _blob[MlDsaOffset..]);

    public static ShroudSecretKey Generate()
    {
        var random = new SecureRandom();
        var blob = new byte[ShroudFormat.SecretKeyBlobLength];

        var kemGenerator = new MLKemKeyPairGenerator();
        kemGenerator.Init(new MLKemKeyGenerationParameters(random, MLKemParameters.ml_kem_768));
        var kemSeed = ((MLKemPrivateKeyParameters)kemGenerator.GenerateKeyPair().Private).GetSeed()
            ?? throw new InvalidOperationException("ML-KEM key was generated without a recoverable seed.");
        kemSeed.CopyTo(blob, 0);

        new X25519PrivateKeyParameters(random).GetEncoded().CopyTo(blob, X25519Offset);

        var dsaGenerator = new MLDsaKeyPairGenerator();
        dsaGenerator.Init(new MLDsaKeyGenerationParameters(random, MLDsaParameters.ml_dsa_65));
        var dsaSeed = ((MLDsaPrivateKeyParameters)dsaGenerator.GenerateKeyPair().Private).GetSeed()
            ?? throw new InvalidOperationException("ML-DSA key was generated without a recoverable seed.");
        dsaSeed.CopyTo(blob, MlDsaOffset);

        return new ShroudSecretKey(blob);
    }

    public ShroudPublicKey GetPublicKey()
    {
        var blob = new byte[ShroudFormat.PublicKeyBlobLength];
        MlKem.GetPublicKeyEncoded().CopyTo(blob, 0);
        X25519.GeneratePublicKey().GetEncoded().CopyTo(blob, ShroudFormat.MlKemPublicKeyLength);
        MlDsa.GetPublicKeyEncoded().CopyTo(blob, ShroudFormat.MlKemPublicKeyLength + ShroudFormat.X25519KeyLength);
        return new ShroudPublicKey(blob);
    }

    public byte[] ToBlob() => (byte[])_blob.Clone();

    public static ShroudSecretKey FromBlob(byte[] blob) => new((byte[])blob.Clone());

    /// <summary>Serialises the key in the clear. Prefer <see cref="ToArmoredString(string)"/>.</summary>
    public string ToArmoredString() => Label + Convert.ToBase64String(_blob);

    /// <summary>Serialises the key wrapped in an Argon2id + AES-256-GCM envelope.</summary>
    public string ToArmoredString(string passphrase, Argon2Settings? argon2 = null) =>
        EncryptedKeyFile.Label + Convert.ToBase64String(
            EncryptedKeyFile.Wrap(_blob, passphrase, argon2 ?? Argon2Settings.KeyFileDefault));

    /// <summary>Parses an unencrypted key file.</summary>
    public static ShroudSecretKey Parse(string text) =>
        new(KeyArmor.Decode(text, Label, "secret key"));

    /// <summary>
    /// Parses a key file, unwrapping it if it is passphrase-protected. <paramref name="passphrase"/>
    /// is only consulted for protected files, so callers can pass a lazily-prompted value.
    /// </summary>
    public static ShroudSecretKey Parse(string text, Func<string> passphrase)
    {
        if (!IsPassphraseProtected(text))
            return Parse(text);

        var envelope = KeyArmor.Decode(text, EncryptedKeyFile.Label, "encrypted secret key");
        return new ShroudSecretKey(EncryptedKeyFile.Unwrap(envelope, passphrase()));
    }

    /// <summary>True if the key file is wrapped and needs a passphrase to open.</summary>
    public static bool IsPassphraseProtected(string text) =>
        KeyArmor.HasLabel(text, EncryptedKeyFile.Label);
}

/// <summary>
/// The Argon2id + AES-256-GCM envelope around a secret key file. Deliberately separate from the
/// container format: it protects 128 bytes at rest and has no need for chunking or signatures.
/// </summary>
internal static class EncryptedKeyFile
{
    public const string Label = "shroud-secret-key-encrypted:v2:";

    private const byte EnvelopeVersion = 1;

    // version(1) || salt(16) || t(4) || m(4) || p(4) || nonce(12)
    private const int PreambleLength = 1 + ShroudFormat.SaltLength + 12 + ShroudFormat.NonceLength;

    public static byte[] Wrap(byte[] secret, string passphrase, Argon2Settings argon2)
    {
        ArgumentException.ThrowIfNullOrEmpty(passphrase);
        argon2.Validate();

        var envelope = new byte[PreambleLength + secret.Length + ShroudFormat.TagLength];
        envelope[0] = EnvelopeVersion;

        RandomNumberGenerator.GetBytes(ShroudFormat.SaltLength).CopyTo(envelope, 1);
        WriteCosts(envelope.AsSpan(1 + ShroudFormat.SaltLength), argon2);
        RandomNumberGenerator.GetBytes(ShroudFormat.NonceLength).CopyTo(envelope, PreambleLength - ShroudFormat.NonceLength);

        var key = DeriveKey(passphrase, envelope);
        try
        {
            using var aes = new AesGcm(key, ShroudFormat.TagLength);
            aes.Encrypt(
                nonce: envelope.AsSpan(PreambleLength - ShroudFormat.NonceLength, ShroudFormat.NonceLength),
                plaintext: secret,
                ciphertext: envelope.AsSpan(PreambleLength, secret.Length),
                tag: envelope.AsSpan(PreambleLength + secret.Length, ShroudFormat.TagLength),
                associatedData: Aad(envelope));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }

        return envelope;
    }

    public static byte[] Unwrap(byte[] envelope, string passphrase)
    {
        ArgumentException.ThrowIfNullOrEmpty(passphrase);

        if (envelope.Length != PreambleLength + ShroudFormat.SecretKeyBlobLength + ShroudFormat.TagLength)
            throw new ShroudFormatException("Encrypted key file has the wrong length.");
        if (envelope[0] != EnvelopeVersion)
            throw new ShroudFormatException($"Unsupported encrypted key file version {envelope[0]}.");

        ReadCosts(envelope.AsSpan(1 + ShroudFormat.SaltLength)).Validate();

        var key = DeriveKey(passphrase, envelope);
        var secret = new byte[ShroudFormat.SecretKeyBlobLength];

        try
        {
            using var aes = new AesGcm(key, ShroudFormat.TagLength);
            aes.Decrypt(
                nonce: envelope.AsSpan(PreambleLength - ShroudFormat.NonceLength, ShroudFormat.NonceLength),
                ciphertext: envelope.AsSpan(PreambleLength, ShroudFormat.SecretKeyBlobLength),
                tag: envelope.AsSpan(PreambleLength + ShroudFormat.SecretKeyBlobLength, ShroudFormat.TagLength),
                plaintext: secret,
                associatedData: Aad(envelope));
        }
        catch (AuthenticationTagMismatchException)
        {
            throw new ShroudFormatException("Wrong passphrase for this key file, or the file was modified.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }

        return secret;
    }

    /// <summary>Everything before the ciphertext is authenticated, so the costs cannot be downgraded.</summary>
    private static byte[] Aad(byte[] envelope)
    {
        var context = ShroudFormat.KeyFileContext;
        var aad = new byte[context.Length + PreambleLength];
        context.CopyTo(aad);
        envelope.AsSpan(0, PreambleLength).CopyTo(aad.AsSpan(context.Length));
        return aad;
    }

    private static byte[] DeriveKey(string passphrase, byte[] envelope)
    {
        var salt = envelope.AsSpan(1, ShroudFormat.SaltLength).ToArray();
        var costs = ReadCosts(envelope.AsSpan(1 + ShroudFormat.SaltLength));
        return Argon2.Derive(passphrase, salt, costs, ShroudFormat.FileKeyLength);
    }

    private static void WriteCosts(Span<byte> destination, Argon2Settings settings)
    {
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(destination[..4], settings.Iterations);
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(destination[4..8], settings.MemoryKib);
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(destination[8..12], settings.Lanes);
    }

    private static Argon2Settings ReadCosts(ReadOnlySpan<byte> source) =>
        new(
            Iterations: System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(source[..4]),
            MemoryKib: System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(source[4..8]),
            Lanes: System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(source[8..12]));
}

internal static class KeyArmor
{
    public static bool HasLabel(string text, string label)
    {
        foreach (var line in Lines(text))
            return line.StartsWith(label, StringComparison.Ordinal);

        return false;
    }

    public static byte[] Decode(string text, string label, string what)
    {
        foreach (var line in Lines(text))
        {
            if (!line.StartsWith(label, StringComparison.Ordinal))
                throw new ShroudFormatException($"Not a SHROUD {what} (expected prefix '{label}').");

            try
            {
                return Convert.FromBase64String(line[label.Length..]);
            }
            catch (FormatException)
            {
                throw new ShroudFormatException($"SHROUD {what} contains malformed base64.");
            }
        }

        throw new ShroudFormatException($"SHROUD {what} file is empty.");
    }

    /// <summary>Yields the payload lines, skipping blanks and '#' comments so key files can carry a header.</summary>
    private static IEnumerable<string> Lines(string text)
    {
        foreach (var line in text.Split('\n'))
        {
            var candidate = line.Trim();
            if (candidate.Length > 0 && !candidate.StartsWith('#'))
                yield return candidate;
        }
    }
}
