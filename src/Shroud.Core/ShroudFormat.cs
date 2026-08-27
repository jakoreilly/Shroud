namespace Shroud.Core;

/// <summary>Wire constants for the SHROUD container format. See FORMAT.md.</summary>
public static class ShroudFormat
{
    public static ReadOnlySpan<byte> Magic => "SHRD"u8;

    public const byte Version = 2;

    /// <summary>Key wrapped with the hybrid ML-KEM-768 + X25519 KEM.</summary>
    public const byte ModeRecipient = 1;

    /// <summary>Key derived from a passphrase with Argon2id.</summary>
    public const byte ModePassphrase = 2;

    /// <summary>ML-KEM-768 + X25519 + ML-DSA-65, HKDF-SHA256, AES-256-GCM.</summary>
    public const byte SuiteDefault = 1;

    /// <summary>Header flag: the container carries an ML-DSA-65 signature trailer.</summary>
    public const byte FlagSigned = 0x01;

    /// <summary>
    /// Header flag: the plaintext is a tar archive that shroud built from a directory. This lives in
    /// the header, not in a filename, so it is covered by the header hash and cannot be flipped to
    /// talk a decryptor into unpacking something that was never an archive.
    /// </summary>
    public const byte FlagArchive = 0x02;

    public const byte KnownFlags = FlagSigned | FlagArchive;

    // Chunk kinds, authenticated in each chunk's associated data.
    public const byte ChunkPayload = 0;
    public const byte ChunkFinalPayload = 1;
    public const byte ChunkSignatureTrailer = 2;

    public const int MlKemPublicKeyLength = 1184;
    public const int MlKemSeedLength = 64;
    public const int MlKemCiphertextLength = 1088;
    public const int X25519KeyLength = 32;
    public const int MlDsaPublicKeyLength = 1952;
    public const int MlDsaSeedLength = 32;
    public const int MlDsaSignatureLength = 3309;

    /// <summary>Serialised public key: ML-KEM public || X25519 public || ML-DSA public.</summary>
    public const int PublicKeyBlobLength = MlKemPublicKeyLength + X25519KeyLength + MlDsaPublicKeyLength;

    /// <summary>Serialised secret key: ML-KEM seed || X25519 scalar || ML-DSA seed.</summary>
    public const int SecretKeyBlobLength = MlKemSeedLength + X25519KeyLength + MlDsaSeedLength;

    /// <summary>Signature trailer plaintext: the sender's full public blob then the signature.</summary>
    public const int SignatureTrailerLength = PublicKeyBlobLength + MlDsaSignatureLength;

    public const int FileKeyLength = 32;
    public const int TagLength = 16;
    public const int NonceLength = 12;
    public const int SaltLength = 16;
    public const int HashLength = 32;

    /// <summary>kind (1) + plaintext length (4).</summary>
    public const int ChunkPrefixLength = 5;

    public const int HeaderPrologueLength = 9;

    public const int RecipientHeaderLength = HeaderPrologueLength + MlKemCiphertextLength + X25519KeyLength;

    public const int PassphraseHeaderLength = HeaderPrologueLength + SaltLength + 12;

    /// <summary>1 MiB of plaintext per AEAD chunk.</summary>
    public const byte DefaultChunkSizeLog = 20;

    public const byte MinChunkSizeLog = 12;
    public const byte MaxChunkSizeLog = 26;

    internal static ReadOnlySpan<byte> HybridKemInfo => "SHROUD2 hybrid-kem v1"u8;

    internal static ReadOnlySpan<byte> PassphraseInfo => "SHROUD2 passphrase v1"u8;

    internal static ReadOnlySpan<byte> SignatureContext => "SHROUD2 signed-container v1"u8;

    internal static ReadOnlySpan<byte> KeyFileContext => "SHROUD2 key-file v1"u8;
}

/// <summary>Thrown when a container is malformed, truncated, or fails authentication.</summary>
public sealed class ShroudFormatException : Exception
{
    public ShroudFormatException(string message) : base(message) { }
}

/// <summary>Thrown when a container's signature is absent, invalid, or from an unexpected sender.</summary>
public sealed class ShroudSignatureException : Exception
{
    public ShroudSignatureException(string message) : base(message) { }
}
