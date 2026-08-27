using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Shroud.Core;

/// <summary>
/// Streams the payload as a sequence of AES-256-GCM chunks so arbitrarily large files never need
/// to fit in memory.
///
/// Each chunk is self-describing on disk -- kind and plaintext length precede the ciphertext --
/// and both of those fields are covered by the chunk's associated data, so the framing cannot be
/// edited without breaking the tag. Being self-describing is what lets a signature trailer follow
/// the payload without the reader needing to look ahead.
///
/// The associated data is (header hash || chunk index || kind || length). That makes the container
/// resistant to the attacks a naive chunked design invites:
///   - truncation: the payload must end with a chunk marked final, so dropping the tail fails;
///   - reordering/duplication: the chunk index is authenticated;
///   - splicing between files: the header hash differs, and with it the file key;
///   - framing edits: kind and length are authenticated.
///
/// Nonces are the chunk index, which is safe only because the file key is unique per file (fresh
/// KEM encapsulation, or a fresh 16-byte Argon2id salt). The key is never reused, so a counter
/// from zero can never repeat a (key, nonce) pair.
/// </summary>
internal static class ChunkedAead
{
    private const int AadLength = ShroudFormat.HashLength + sizeof(ulong) + 1 + sizeof(int);

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> and returns its SHA-256 and length, which the caller
    /// needs in order to sign the container. Hashing happens on the same pass as encryption.
    /// </summary>
    public static PayloadSummary EncryptPayload(
        Stream plaintext,
        Stream output,
        byte[] fileKey,
        byte[] headerHash,
        int chunkSize)
    {
        using var aes = new AesGcm(fileKey, ShroudFormat.TagLength);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        var buffer = new byte[chunkSize];
        var framed = new byte[ShroudFormat.ChunkPrefixLength + chunkSize + ShroudFormat.TagLength];

        ulong index = 0;
        long totalLength = 0;

        while (true)
        {
            int read = ReadUpTo(plaintext, buffer);
            bool isFinal = read < chunkSize;

            hash.AppendData(buffer, 0, read);
            totalLength += read;

            WriteChunk(
                aes,
                output,
                framed,
                headerHash,
                index,
                isFinal ? ShroudFormat.ChunkFinalPayload : ShroudFormat.ChunkPayload,
                buffer.AsSpan(0, read));

            index = checked(index + 1);

            if (isFinal)
                break;
        }

        return new PayloadSummary(hash.GetHashAndReset(), totalLength, index);
    }

    /// <summary>Appends the signature trailer as one further AEAD chunk.</summary>
    public static void WriteSignatureTrailer(
        Stream output,
        byte[] fileKey,
        byte[] headerHash,
        ulong index,
        ReadOnlySpan<byte> trailer)
    {
        using var aes = new AesGcm(fileKey, ShroudFormat.TagLength);
        var framed = new byte[ShroudFormat.ChunkPrefixLength + trailer.Length + ShroudFormat.TagLength];
        WriteChunk(aes, output, framed, headerHash, index, ShroudFormat.ChunkSignatureTrailer, trailer);
    }

    /// <summary>
    /// Decrypts the payload, returning its SHA-256, its length, and the signature trailer if one
    /// was present. Enforces that the chunk sequence is exactly
    /// (payload*, final payload, trailer?) and that nothing follows it.
    /// </summary>
    public static DecryptedPayload DecryptPayload(
        Stream input,
        Stream output,
        byte[] fileKey,
        byte[] headerHash,
        int chunkSize,
        bool expectTrailer)
    {
        using var aes = new AesGcm(fileKey, ShroudFormat.TagLength);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        var plaintext = new byte[Math.Max(chunkSize, ShroudFormat.SignatureTrailerLength)];

        // Hoisted for the same reason `framed` is on the encrypt side: at the default chunk size a
        // per-chunk array would be a Large Object Heap allocation for every chunk of the file.
        var body = new byte[plaintext.Length + ShroudFormat.TagLength];

        Span<byte> aad = stackalloc byte[AadLength];
        ulong index = 0;
        long totalLength = 0;
        bool payloadComplete = false;
        byte[]? trailer = null;

        while (true)
        {
            var chunk = ReadChunkPrefix(input, index, chunkSize, payloadComplete);
            if (chunk is null)
                break;

            var (kind, length) = chunk.Value;

            if (kind == ShroudFormat.ChunkSignatureTrailer && !expectTrailer)
                throw new ShroudFormatException("Container carries a signature trailer but its header does not declare one.");

            ReadExactly(input, body, length + ShroudFormat.TagLength, index);

            BuildAad(aad, headerHash, index, kind, length);

            try
            {
                aes.Decrypt(
                    nonce: Nonce(index),
                    ciphertext: body.AsSpan(0, length),
                    tag: body.AsSpan(length, ShroudFormat.TagLength),
                    plaintext: plaintext.AsSpan(0, length),
                    associatedData: aad);
            }
            catch (AuthenticationTagMismatchException)
            {
                throw new ShroudFormatException(index == 0
                    ? "Authentication failed on the first chunk: wrong key, wrong passphrase, or the container was modified."
                    : $"Authentication failed on chunk {index}: the container was modified or truncated.");
            }

            switch (kind)
            {
                case ShroudFormat.ChunkPayload:
                case ShroudFormat.ChunkFinalPayload:
                    hash.AppendData(plaintext, 0, length);
                    totalLength += length;
                    output.Write(plaintext, 0, length);
                    payloadComplete = kind == ShroudFormat.ChunkFinalPayload;
                    break;

                case ShroudFormat.ChunkSignatureTrailer:
                    trailer = plaintext.AsSpan(0, length).ToArray();
                    break;
            }

            index = checked(index + 1);

            if (trailer is not null)
                break;
        }

        if (!payloadComplete)
            throw new ShroudFormatException("Container is truncated: no chunk was marked as the end of the payload.");

        if (expectTrailer && trailer is null)
            throw new ShroudFormatException("Container declares a signature but the signature trailer is missing.");

        // Nothing may follow the last expected chunk.
        if (input.ReadByte() >= 0)
            throw new ShroudFormatException("Container has trailing data after its final chunk.");

        return new DecryptedPayload(hash.GetHashAndReset(), totalLength, trailer);
    }

    private static void WriteChunk(
        AesGcm aes,
        Stream output,
        byte[] framed,
        byte[] headerHash,
        ulong index,
        byte kind,
        ReadOnlySpan<byte> payload)
    {
        framed[0] = kind;
        BinaryPrimitives.WriteInt32BigEndian(framed.AsSpan(1, 4), payload.Length);

        Span<byte> aad = stackalloc byte[AadLength];
        BuildAad(aad, headerHash, index, kind, payload.Length);

        aes.Encrypt(
            nonce: Nonce(index),
            plaintext: payload,
            ciphertext: framed.AsSpan(ShroudFormat.ChunkPrefixLength, payload.Length),
            tag: framed.AsSpan(ShroudFormat.ChunkPrefixLength + payload.Length, ShroudFormat.TagLength),
            associatedData: aad);

        output.Write(framed, 0, ShroudFormat.ChunkPrefixLength + payload.Length + ShroudFormat.TagLength);
    }

    /// <summary>
    /// Reads and validates a chunk prefix, returning null at a clean end of stream. Lengths are
    /// range-checked here, before anything is allocated or read, because they come from an
    /// untrusted file.
    /// </summary>
    private static (byte Kind, int Length)? ReadChunkPrefix(
        Stream input,
        ulong index,
        int chunkSize,
        bool payloadComplete)
    {
        var prefix = new byte[ShroudFormat.ChunkPrefixLength];
        int read = ReadUpTo(input, prefix);

        if (read == 0)
            return null;
        if (read < ShroudFormat.ChunkPrefixLength)
            throw new ShroudFormatException($"Container is truncated inside the framing of chunk {index}.");

        byte kind = prefix[0];
        int length = BinaryPrimitives.ReadInt32BigEndian(prefix.AsSpan(1, 4));

        if (length < 0)
            throw new ShroudFormatException($"Chunk {index} declares a negative length.");

        switch (kind)
        {
            case ShroudFormat.ChunkPayload:
                if (payloadComplete)
                    throw new ShroudFormatException($"Chunk {index} continues a payload that was already marked complete.");
                if (length != chunkSize)
                    throw new ShroudFormatException($"Non-final chunk {index} must hold exactly {chunkSize} bytes, declares {length}.");
                break;

            case ShroudFormat.ChunkFinalPayload:
                if (payloadComplete)
                    throw new ShroudFormatException($"Chunk {index} marks a second end of payload.");
                if (length > chunkSize)
                    throw new ShroudFormatException($"Chunk {index} declares {length} bytes, more than the {chunkSize}-byte chunk size.");
                break;

            case ShroudFormat.ChunkSignatureTrailer:
                if (!payloadComplete)
                    throw new ShroudFormatException($"Chunk {index} is a signature trailer but the payload has not ended.");
                if (length != ShroudFormat.SignatureTrailerLength)
                    throw new ShroudFormatException($"Signature trailer must be {ShroudFormat.SignatureTrailerLength} bytes, declares {length}.");
                break;

            default:
                throw new ShroudFormatException($"Chunk {index} has unknown kind {kind}.");
        }

        return (kind, length);
    }

    private static void BuildAad(Span<byte> aad, byte[] headerHash, ulong index, byte kind, int length)
    {
        headerHash.CopyTo(aad);
        BinaryPrimitives.WriteUInt64BigEndian(aad.Slice(ShroudFormat.HashLength, sizeof(ulong)), index);
        aad[ShroudFormat.HashLength + sizeof(ulong)] = kind;
        BinaryPrimitives.WriteInt32BigEndian(aad.Slice(ShroudFormat.HashLength + sizeof(ulong) + 1, sizeof(int)), length);
    }

    private static byte[] Nonce(ulong index)
    {
        var nonce = new byte[ShroudFormat.NonceLength];
        BinaryPrimitives.WriteUInt64BigEndian(nonce.AsSpan(ShroudFormat.NonceLength - sizeof(ulong)), index);
        return nonce;
    }

    private static void ReadExactly(Stream input, byte[] buffer, int count, ulong index)
    {
        if (ReadUpTo(input, buffer, count) != count)
            throw new ShroudFormatException($"Container is truncated inside chunk {index}.");
    }

    private static int ReadUpTo(Stream stream, byte[] buffer) => ReadUpTo(stream, buffer, buffer.Length);

    /// <summary>
    /// Reads <paramref name="count"/> bytes into the front of the buffer, returning short only at
    /// end of stream. Byte-array rather than Span on purpose: the input is wrapped in a progress
    /// stream that overrides only Read(byte[], int, int), so a span read would fall back to
    /// Stream's rent-and-copy path and give back what the reused buffer saves.
    /// </summary>
    private static int ReadUpTo(Stream stream, byte[] buffer, int count)
    {
        int total = 0;
        while (total < count)
        {
            int n = stream.Read(buffer, total, count - total);
            if (n == 0)
                break;
            total += n;
        }

        return total;
    }
}

internal readonly record struct PayloadSummary(byte[] Hash, long Length, ulong NextChunkIndex);

internal readonly record struct DecryptedPayload(byte[] Hash, long Length, byte[]? SignatureTrailer);
