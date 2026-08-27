using System.Formats.Tar;

namespace Shroud.App;

/// <summary>
/// Directory support: shroud encrypts one stream, so a directory becomes a tar archive first. The
/// header records that it is an archive, so the decryptor unpacks it without being told.
///
/// Extraction only ever runs on plaintext that has already been fully authenticated -- and, if the
/// container was signed, verified -- because the CLI stages the whole decryption before unpacking.
/// Even so, a tar from a counterparty is untrusted input: <see cref="ExtractTo"/> refuses entries
/// that escape the destination and refuses every entry type except plain files and directories, so
/// a hostile archive cannot plant a symlink or write outside the folder you named.
/// </summary>
public static class Archive
{
    public static int CreateFrom(string directory, Stream destination)
    {
        int entries = Directory.EnumerateFileSystemEntries(directory, "*", SearchOption.AllDirectories).Count();

        TarFile.CreateFromDirectory(directory, destination, includeBaseDirectory: false);

        return entries;
    }

    public static int ExtractTo(Stream source, string destination)
    {
        Directory.CreateDirectory(destination);

        // Compare against the real, fully resolved destination: the check below is only as good as
        // the path it is comparing to.
        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(destination));
        var rootPrefix = root + Path.DirectorySeparatorChar;

        using var reader = new TarReader(source);
        int extracted = 0;

        while (reader.GetNextEntry() is { } entry)
        {
            if (entry.EntryType is not (TarEntryType.RegularFile or TarEntryType.V7RegularFile
                or TarEntryType.Directory))
            {
                throw new ShroudArchiveException(
                    $"Archive entry '{entry.Name}' is a {entry.EntryType}, which shroud will not extract. "
                        + "Only plain files and directories are unpacked.");
            }

            var target = Resolve(entry.Name, root, rootPrefix);

            if (entry.EntryType is TarEntryType.Directory)
            {
                Directory.CreateDirectory(target);
                continue;
            }

            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            entry.ExtractToFile(target, overwrite: true);
            extracted++;
        }

        return extracted;
    }

    /// <summary>
    /// Turns an entry name into an absolute path inside the destination, or refuses. Absolute
    /// names, <c>..</c> traversal and Windows drive or stream qualifiers all end up outside the
    /// destination once resolved, so one prefix check after normalisation catches them all.
    /// </summary>
    private static string Resolve(string entryName, string root, string rootPrefix)
    {
        if (entryName.Length == 0 || entryName.Contains('\0'))
            throw new ShroudArchiveException("Archive contains an entry with an unusable name.");

        string full;

        try
        {
            full = Path.GetFullPath(Path.Combine(root, entryName));
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new ShroudArchiveException($"Archive entry '{entryName}' has an unusable name.");
        }

        var normalised = Path.TrimEndingDirectorySeparator(full);

        if (!normalised.StartsWith(rootPrefix, StringComparison.Ordinal)
            && !string.Equals(normalised, root, StringComparison.Ordinal))
        {
            throw new ShroudArchiveException(
                $"Archive entry '{entryName}' would be written outside the destination directory. "
                    + "Refusing to extract it.");
        }

        return full;
    }
}

/// <summary>Thrown when an archive is malformed or tries to write outside its destination.</summary>
public sealed class ShroudArchiveException(string message) : Exception(message);
