using Shroud.Core;

namespace Shroud.App;

/// <summary>What the UI is allowed to ask for. The implementation is a thin shell over ShroudFile
/// plus the staging orchestration; ViewModels take this interface so they can be tested with a
/// fake that never touches the filesystem or spends a second in Argon2.</summary>
public interface IShroudEngine
{
    /// <summary>Reads the header only. No key required; reports IsContainer = false rather than
    /// throwing if the file is not a container, which is how the Files screen decides which panel
    /// to show.</summary>
    ContainerSummary Inspect(string path);

    void Encrypt(EncryptRequest request, IProgress<double>? progress, CancellationToken token);

    /// <summary>Decrypts, verifies, and only then moves or extracts. Returns what was established
    /// about origin.</summary>
    SignatureReport Decrypt(DecryptRequest request, IProgress<double>? progress, CancellationToken token);
}

public sealed record ContainerSummary(
    bool IsContainer, bool IsSigned, bool IsArchive, bool IsPassphraseMode, int ChunkSizeBytes);

public sealed record EncryptRequest(
    string InputPath,
    string OutputPath,
    ShroudPublicKey? Recipient,
    string? Passphrase,
    ShroudSecretKey? Sender,
    bool Force);

public sealed record DecryptRequest(
    string InputPath,
    string OutputPath,
    ShroudSecretKey? Key,
    string? Passphrase,
    ShroudPublicKey? ExpectedSender,
    bool RequireSigned,
    bool Extract,
    bool Force);
