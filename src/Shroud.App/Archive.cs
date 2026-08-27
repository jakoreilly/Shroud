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
///
/// Escaping is checked twice, because the two checks catch different things. <see cref="Resolve"/>
/// is lexical: it normalises the entry name and catches <c>..</c>, absolute paths and Windows drive
/// qualifiers. Normalisation does not follow symlinks, though, so a link that was already sitting
/// in the destination before extraction started would still be written through. That is what
/// <see cref="EnsureInside"/> catches, by resolving each directory as the tree is descended.
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

        // Compare against the real, fully resolved destination: the checks below are only as good
        // as the path they are comparing to. Links are resolved here too, so a destination that is
        // itself a symlink -- which is perfectly legitimate -- is not refused by its own check.
        var root = Path.TrimEndingDirectorySeparator(RealPath(Path.GetFullPath(destination)));
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
                CreateDirectories(entry.Name, target, root, rootPrefix);
                continue;
            }

            CreateDirectories(entry.Name, Path.GetDirectoryName(target)!, root, rootPrefix);
            RefuseExistingLink(entry.Name, target);

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

    /// <summary>
    /// Creates <paramref name="directory"/> and any missing parents one level at a time, checking
    /// after each level that we are still inside the destination. Creating the whole chain in one
    /// call would descend through a pre-existing symlink before anything had a chance to look at
    /// it; one level at a time means each link is caught before the level below it is touched.
    /// </summary>
    private static void CreateDirectories(string entryName, string directory, string root, string rootPrefix)
    {
        var relative = Path.GetRelativePath(root, directory);

        if (relative is "" or ".")
            return;

        var current = root;

        foreach (var segment in relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar))
        {
            if (segment.Length == 0)
                continue;

            // Safe to create: this level's own parent was checked on the previous iteration.
            current = Path.Combine(current, segment);
            Directory.CreateDirectory(current);
            EnsureInside(entryName, current, root, rootPrefix);
        }
    }

    /// <summary>Refuses a directory that, once its links are followed, lands outside the destination.</summary>
    private static void EnsureInside(string entryName, string directory, string root, string rootPrefix)
    {
        var real = Path.TrimEndingDirectorySeparator(RealPath(directory));

        if (!real.StartsWith(rootPrefix, StringComparison.Ordinal)
            && !string.Equals(real, root, StringComparison.Ordinal))
        {
            throw new ShroudArchiveException(
                $"Archive entry '{entryName}' resolves through a link that leaves the destination "
                    + "directory. Refusing to extract it.");
        }
    }

    /// <summary>
    /// Refuses to write over an existing symlink. The directories above the target have been
    /// checked by this point, but the target itself may be a link, and writing to it would follow
    /// it wherever it points.
    /// </summary>
    private static void RefuseExistingLink(string entryName, string target)
    {
        var existing = new FileInfo(target);

        if (existing.Exists && existing.ResolveLinkTarget(returnFinalTarget: false) is not null)
        {
            throw new ShroudArchiveException(
                $"Archive entry '{entryName}' would be written through an existing link at the "
                    + "destination. Refusing to extract it.");
        }
    }

    /// <summary>Where a directory really lands, following any symlink; the path itself if it is not one.</summary>
    private static string RealPath(string directory) =>
        new DirectoryInfo(directory).ResolveLinkTarget(returnFinalTarget: true)?.FullName ?? directory;
}

/// <summary>Thrown when an archive is malformed or tries to write outside its destination.</summary>
public sealed class ShroudArchiveException(string message) : Exception(message);
