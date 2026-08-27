using Shroud.Core;

namespace Shroud.App;

/// <summary>
/// The one implementation of <see cref="IShroudEngine"/>: a thin shell over <see cref="ShroudFile"/> and
/// the staging/archive orchestration in <see cref="FileOperations"/> and <see cref="Archive"/>.
///
/// This is the same ordering the CLI uses -- staging, then verify, then (only for an archive the
/// header actually marks) extract -- so the UI cannot drift from it by construction.
/// </summary>
public sealed class ShroudEngine(ShroudWorkspace workspace) : IShroudEngine
{
    public ContainerSummary Inspect(string path)
    {
        using var input = File.OpenRead(path);

        FileHeader header;
        try
        {
            header = ShroudFile.ReadHeader(input);
        }
        catch (ShroudFormatException)
        {
            return new ContainerSummary(IsContainer: false, IsSigned: false, IsArchive: false, IsPassphraseMode: false, ChunkSizeBytes: 0);
        }

        return new ContainerSummary(
            IsContainer: true,
            IsSigned: header.IsSigned,
            IsArchive: header.IsArchive,
            IsPassphraseMode: header.Mode == ShroudFormat.ModePassphrase,
            ChunkSizeBytes: header.ChunkSize);
    }

    public void Encrypt(EncryptRequest request, IProgress<double>? progress, CancellationToken token)
    {
        FileOperations.RefuseExistingFile(request.OutputPath, request.Force);

        bool isDirectory = Directory.Exists(request.InputPath);
        var inputPath = request.InputPath;
        var archivePath = isDirectory ? request.OutputPath + ".shroud-archive" : null;

        try
        {
            if (archivePath is not null)
            {
                using (var tar = File.Create(archivePath))
                    Archive.CreateFrom(inputPath, tar);

                inputPath = archivePath;
            }

            var sourceLength = new FileInfo(inputPath).Length;

            FileOperations.WithStaging(inputPath, request.OutputPath, request.Force, (input, output) =>
            {
                using var tracked = new ProgressStream(input, sourceLength, progress, token);

                if (request.Recipient is not null)
                {
                    ShroudFile.Encrypt(tracked, output, request.Recipient, request.Sender, archive: isDirectory);
                }
                else
                {
                    ArgumentException.ThrowIfNullOrEmpty(request.Passphrase);
                    ShroudFile.EncryptWithPassphrase(tracked, output, request.Passphrase, request.Sender, archive: isDirectory);
                }
            });
        }
        finally
        {
            if (archivePath is not null)
                FileOperations.TryDelete(archivePath);
        }
    }

    public SignatureReport Decrypt(DecryptRequest request, IProgress<double>? progress, CancellationToken token)
    {
        var policy = request.ExpectedSender is not null
            ? VerificationPolicy.From(request.ExpectedSender)
            : request.RequireSigned
                ? VerificationPolicy.Required
                : VerificationPolicy.Optional;

        var sourceLength = new FileInfo(request.InputPath).Length;
        DecryptionResult? result = null;

        FileOperations.WithStaging(
            request.InputPath,
            request.OutputPath,
            request.Force,
            (input, output) =>
            {
                using var tracked = new ProgressStream(input, sourceLength, progress, token);

                result = request.Key is not null
                    ? ShroudFile.Decrypt(tracked, output, request.Key, policy)
                    : ShroudFile.DecryptWithPassphrase(tracked, output, RequirePassphrase(request), policy);
            },
            complete: (staging, destination) =>
            {
                // Unpacking happens only here, after the whole container -- signature included --
                // has verified. The Extract flag is the caller's preference; result.IsArchive is
                // the authenticated header bit an attacker cannot forge. Both must hold.
                if (result is { IsArchive: true } && request.Extract)
                {
                    FileOperations.RefuseNonEmptyDirectory(destination, request.Force);

                    using (var tar = File.OpenRead(staging))
                        Archive.ExtractTo(tar, destination);

                    File.Delete(staging);
                    return;
                }

                File.Move(staging, destination, overwrite: true);
            });

        return SignatureReport.For(result!, workspace);
    }

    private static string RequirePassphrase(DecryptRequest request)
    {
        ArgumentException.ThrowIfNullOrEmpty(request.Passphrase);
        return request.Passphrase;
    }
}
