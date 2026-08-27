namespace Shroud.App;

/// <summary>
/// Staging and destination-safety helpers shared by every front end that writes decrypted or
/// encrypted output. Keeping this in one place is what makes "nothing unverified ever lands at the
/// destination" true regardless of which caller drives it.
/// </summary>
public static class FileOperations
{
    /// <summary>
    /// Runs a stream-to-stream operation, writing to a temporary file beside the destination and
    /// putting it in place only on success.
    ///
    /// This is what makes signature verification meaningful. A signature covers the whole
    /// plaintext, so it can only be checked once the last chunk has been read -- if we wrote
    /// straight to the destination, a caller could act on an unverified file before the
    /// verification failed. Staging means the destination only ever appears fully verified, and it
    /// is also what lets an archive be unpacked only after the container has been checked.
    ///
    /// Note the cleanup is an ordinary delete, not a secure erase; on media you do not control,
    /// decrypt somewhere you do.
    /// </summary>
    public static void WithStaging(
        string inputPath,
        string outputPath,
        bool force,
        Action<Stream, Stream> body,
        Action<string, string>? complete = null)
    {
        RefuseExistingFile(outputPath, force);

        var staging = outputPath + ".shroud-partial";

        try
        {
            using (var input = File.OpenRead(inputPath))
            using (var output = File.Create(staging))
            {
                body(input, output);
            }

            if (complete is null)
                File.Move(staging, outputPath, overwrite: true);
            else
                complete(staging, outputPath);
        }
        catch
        {
            TryDelete(staging);
            throw;
        }
    }

    public static void RefuseExistingFile(string path, bool force)
    {
        if (File.Exists(path) && !force)
            throw new ShroudWorkspaceException($"{path} already exists. Pass --force to overwrite.");
    }

    public static void RefuseNonEmptyDirectory(string path, bool force)
    {
        if (!force && Directory.Exists(path) && Directory.EnumerateFileSystemEntries(path).Any())
            throw new ShroudWorkspaceException($"{path} already exists and is not empty. Pass --force to unpack into it.");
    }

    public static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
                File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"shroud: warning: could not remove incomplete output {path}: {ex.Message}");
        }
    }
}
