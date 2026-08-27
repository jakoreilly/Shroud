using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Shroud.Core;

/// <summary>
/// The cleartext prologue of a SHROUD container. Its SHA-256 is mixed into file-key derivation,
/// into every chunk's associated data, and into the signed message, so any edit to the header
/// breaks decryption.
/// </summary>
public sealed class FileHeader
{
    public required byte Mode { get; init; }

    public required byte Suite { get; init; }

    public required byte ChunkSizeLog { get; init; }

    public required byte Flags { get; init; }

    // Mode 1 (recipient) only.
    public byte[]? KemCiphertext { get; init; }

    public byte[]? EphemeralX25519PublicKey { get; init; }

    // Mode 2 (passphrase) only.
    public byte[]? Salt { get; init; }

    public Argon2Settings? Argon2 { get; init; }

    public int ChunkSize => 1 << ChunkSizeLog;

    public bool IsSigned => (Flags & ShroudFormat.FlagSigned) != 0;

    public bool IsArchive => (Flags & ShroudFormat.FlagArchive) != 0;

    public static FileHeader ForRecipient(
        byte[] kemCiphertext,
        byte[] ephemeralPublicKey,
        byte chunkSizeLog,
        bool signed,
        bool archive = false) =>
        new()
        {
            Mode = ShroudFormat.ModeRecipient,
            Suite = ShroudFormat.SuiteDefault,
            ChunkSizeLog = chunkSizeLog,
            Flags = ToFlags(signed, archive),
            KemCiphertext = kemCiphertext,
            EphemeralX25519PublicKey = ephemeralPublicKey,
        };

    public static FileHeader ForPassphrase(
        byte[] salt,
        Argon2Settings argon2,
        byte chunkSizeLog,
        bool signed,
        bool archive = false) =>
        new()
        {
            Mode = ShroudFormat.ModePassphrase,
            Suite = ShroudFormat.SuiteDefault,
            ChunkSizeLog = chunkSizeLog,
            Flags = ToFlags(signed, archive),
            Salt = salt,
            Argon2 = argon2,
        };

    public byte[] ToBytes()
    {
        using var ms = new MemoryStream();
        ms.Write(ShroudFormat.Magic);
        ms.WriteByte(ShroudFormat.Version);
        ms.WriteByte(Mode);
        ms.WriteByte(Suite);
        ms.WriteByte(ChunkSizeLog);
        ms.WriteByte(Flags);

        switch (Mode)
        {
            case ShroudFormat.ModeRecipient:
                ms.Write(KemCiphertext ?? throw new InvalidOperationException("Missing KEM ciphertext."));
                ms.Write(EphemeralX25519PublicKey ?? throw new InvalidOperationException("Missing ephemeral key."));
                break;

            case ShroudFormat.ModePassphrase:
                var settings = Argon2 ?? throw new InvalidOperationException("Missing Argon2 settings.");
                ms.Write(Salt ?? throw new InvalidOperationException("Missing salt."));
                WriteInt32(ms, settings.Iterations);
                WriteInt32(ms, settings.MemoryKib);
                WriteInt32(ms, settings.Lanes);
                break;

            default:
                throw new InvalidOperationException($"Unknown mode {Mode}.");
        }

        return ms.ToArray();
    }

    /// <summary>Reads a header, leaving <paramref name="input"/> positioned at the first chunk.</summary>
    public static FileHeader Read(Stream input)
    {
        Span<byte> prologue = stackalloc byte[ShroudFormat.HeaderPrologueLength];
        ReadExactly(input, prologue);

        if (!prologue[..4].SequenceEqual(ShroudFormat.Magic))
            throw new ShroudFormatException("Not a Shroud container (bad magic).");
        if (prologue[4] != ShroudFormat.Version)
            throw new ShroudFormatException($"Unsupported container version {prologue[4]}; this build reads version {ShroudFormat.Version}.");

        byte mode = prologue[5];
        byte suite = prologue[6];
        byte chunkSizeLog = prologue[7];
        byte flags = prologue[8];

        if (suite != ShroudFormat.SuiteDefault)
            throw new ShroudFormatException($"Unsupported cipher suite {suite}.");
        if (chunkSizeLog < ShroudFormat.MinChunkSizeLog || chunkSizeLog > ShroudFormat.MaxChunkSizeLog)
            throw new ShroudFormatException($"Chunk size 2^{chunkSizeLog} out of supported range.");

        // Refuse flags we do not understand rather than ignoring them: an unknown flag could
        // mean the container carries something we would silently skip.
        if ((flags & ~ShroudFormat.KnownFlags) != 0)
            throw new ShroudFormatException($"Container sets unknown header flags (0x{flags:x2}).");

        bool signed = (flags & ShroudFormat.FlagSigned) != 0;
        bool archive = (flags & ShroudFormat.FlagArchive) != 0;

        switch (mode)
        {
            case ShroudFormat.ModeRecipient:
            {
                var kemCt = ReadBytes(input, ShroudFormat.MlKemCiphertextLength);
                var ephPk = ReadBytes(input, ShroudFormat.X25519KeyLength);
                return ForRecipient(kemCt, ephPk, chunkSizeLog, signed, archive);
            }

            case ShroudFormat.ModePassphrase:
            {
                var salt = ReadBytes(input, ShroudFormat.SaltLength);
                var costs = ReadBytes(input, 12);
                var settings = new Argon2Settings(
                    Iterations: BinaryPrimitives.ReadInt32BigEndian(costs.AsSpan(0, 4)),
                    MemoryKib: BinaryPrimitives.ReadInt32BigEndian(costs.AsSpan(4, 4)),
                    Lanes: BinaryPrimitives.ReadInt32BigEndian(costs.AsSpan(8, 4)));
                settings.Validate();
                return ForPassphrase(salt, settings, chunkSizeLog, signed, archive);
            }

            default:
                throw new ShroudFormatException($"Unknown container mode {mode}.");
        }
    }

    private static byte ToFlags(bool signed, bool archive) =>
        (byte)((signed ? ShroudFormat.FlagSigned : 0) | (archive ? ShroudFormat.FlagArchive : 0));

    /// <summary>SHA-256 over the serialised header; binds every header field to the derived key.</summary>
    public byte[] ComputeHash() => SHA256.HashData(ToBytes());

    private static void WriteInt32(Stream s, int value)
    {
        Span<byte> buf = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(buf, value);
        s.Write(buf);
    }

    private static byte[] ReadBytes(Stream input, int count)
    {
        var buf = new byte[count];
        ReadExactly(input, buf);
        return buf;
    }

    private static void ReadExactly(Stream input, Span<byte> destination)
    {
        int read = 0;
        while (read < destination.Length)
        {
            int n = input.Read(destination[read..]);
            if (n == 0)
                throw new ShroudFormatException("Container is truncated inside the header.");
            read += n;
        }
    }
}
