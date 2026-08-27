using System.Formats.Tar;
using Shroud.Core;

namespace Shroud.Cli.Tests;

/// <summary>
/// Directory support, and the part of it that matters: an archive from someone else is untrusted
/// input, and unpacking it must not be able to write outside the folder you named.
/// </summary>
public class CliDirectoryTests
{
    [Fact]
    public void Directory_RoundTripsWithItsStructureIntact()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("bob", TestKeys.Bob);

        Directory.CreateDirectory(ws.Path("records/invoices"));
        File.WriteAllText(ws.Path("records/readme.txt"), "top level");
        File.WriteAllBytes(ws.Path("records/invoices/2026.bin"), [1, 2, 3, 4]);

        var encrypt = ws.Run("encrypt", "-i", ws.Path("records"), "-o", ws.Path("out.shroud"), "-r", ws.Path("bob.pub"));
        var decrypt = ws.Run("decrypt", "-i", ws.Path("out.shroud"), "-o", ws.Path("restored"), "-k", ws.Path("bob.key"));

        Assert.Equal(Exit.Ok, encrypt.ExitCode);
        Assert.Contains("packed", encrypt.Stderr);
        Assert.Equal(Exit.Ok, decrypt.ExitCode);
        Assert.Contains("extracted", decrypt.Stderr);

        Assert.Equal("top level", File.ReadAllText(ws.Path("restored/readme.txt")));
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, File.ReadAllBytes(ws.Path("restored/invoices/2026.bin")));

        // The tar built along the way is scratch, not output.
        Assert.Empty(ws.LeftoverPartials());
    }

    [Fact]
    public void ArchiveFlagIsRecordedInTheHeader()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("bob", TestKeys.Bob);
        Directory.CreateDirectory(ws.Path("records"));
        File.WriteAllText(ws.Path("records/a.txt"), "x");

        ws.Run("encrypt", "-i", ws.Path("records"), "-o", ws.Path("dir.shroud"), "-r", ws.Path("bob.pub"));
        ws.WriteBytes("single.bin", [1]);
        ws.Run("encrypt", "-i", ws.Path("single.bin"), "-o", ws.Path("file.shroud"), "-r", ws.Path("bob.pub"));

        Assert.Contains("content:     directory archive (tar)", ws.Run("info", "-i", ws.Path("dir.shroud")).Stdout);
        Assert.Contains("content:     single file", ws.Run("info", "-i", ws.Path("file.shroud")).Stdout);
    }

    [Fact]
    public void NoExtract_WritesTheRawArchiveInstead()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("bob", TestKeys.Bob);
        Directory.CreateDirectory(ws.Path("records"));
        File.WriteAllText(ws.Path("records/a.txt"), "x");

        ws.Run("encrypt", "-i", ws.Path("records"), "-o", ws.Path("out.shroud"), "-r", ws.Path("bob.pub"));
        var decrypt = ws.Run("decrypt", "-i", ws.Path("out.shroud"), "-o", ws.Path("out.tar"),
            "-k", ws.Path("bob.key"), "--no-extract");

        Assert.Equal(Exit.Ok, decrypt.ExitCode);
        Assert.True(ws.Exists("out.tar"));
        Assert.False(Directory.Exists(ws.Path("out.tar")));
    }

    [Fact]
    public void ExistingNonEmptyDestination_IsNotUnpackedIntoWithoutForce()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("bob", TestKeys.Bob);
        Directory.CreateDirectory(ws.Path("records"));
        File.WriteAllText(ws.Path("records/a.txt"), "x");
        Directory.CreateDirectory(ws.Path("restored"));
        File.WriteAllText(ws.Path("restored/keep-me.txt"), "existing");

        ws.Run("encrypt", "-i", ws.Path("records"), "-o", ws.Path("out.shroud"), "-r", ws.Path("bob.pub"));
        var decrypt = ws.Run("decrypt", "-i", ws.Path("out.shroud"), "-o", ws.Path("restored"), "-k", ws.Path("bob.key"));

        Assert.Equal(Exit.Usage, decrypt.ExitCode);
        Assert.Contains("--force", decrypt.Stderr);
        Assert.Equal("existing", File.ReadAllText(ws.Path("restored/keep-me.txt")));
        Assert.False(ws.Exists("restored/a.txt"));
        Assert.Empty(ws.LeftoverPartials());
    }

    [Fact]
    public void ArchiveEntryEscapingTheDestination_IsRefused()
    {
        using var ws = new Workspace();

        // A hostile archive, sealed and signed correctly. The container is completely valid; the
        // attack is entirely in the entry name.
        var container = HostileArchive(entry => entry("../escaped.txt", TarEntryType.RegularFile));
        ws.WriteBytes("evil.shroud", container);
        ws.WriteIdentity("bob", TestKeys.Bob);

        var decrypt = ws.Run("decrypt", "-i", ws.Path("evil.shroud"), "-o", ws.Path("restored"), "-k", ws.Path("bob.key"));

        Assert.Equal(Exit.BadContainer, decrypt.ExitCode);
        Assert.Contains("outside the destination", decrypt.Stderr);
        Assert.False(ws.Exists("escaped.txt"));
        Assert.Empty(ws.LeftoverPartials());
    }

    [Fact]
    public void ArchiveEntryWithAnAbsolutePath_IsRefused()
    {
        using var ws = new Workspace();
        var container = HostileArchive(entry => entry("/tmp/shroud-escaped.txt", TarEntryType.RegularFile));
        ws.WriteBytes("evil.shroud", container);
        ws.WriteIdentity("bob", TestKeys.Bob);

        var decrypt = ws.Run("decrypt", "-i", ws.Path("evil.shroud"), "-o", ws.Path("restored"), "-k", ws.Path("bob.key"));

        Assert.Equal(Exit.BadContainer, decrypt.ExitCode);
        Assert.Contains("outside the destination", decrypt.Stderr);
    }

    [Fact]
    public void ArchiveContainingASymlink_IsRefused()
    {
        using var ws = new Workspace();
        var container = HostileArchive(entry => entry("link", TarEntryType.SymbolicLink));
        ws.WriteBytes("evil.shroud", container);
        ws.WriteIdentity("bob", TestKeys.Bob);

        var decrypt = ws.Run("decrypt", "-i", ws.Path("evil.shroud"), "-o", ws.Path("restored"), "-k", ws.Path("bob.key"));

        // Symlinks are how an archive turns a later write into a write somewhere else entirely.
        Assert.Equal(Exit.BadContainer, decrypt.ExitCode);
        Assert.Contains("will not extract", decrypt.Stderr);
        Assert.Empty(ws.LeftoverPartials());
    }

    [Fact]
    public void ArchiveEntryWritingThroughAPreExistingLink_IsRefused()
    {
        using var ws = new Workspace();

        // The destination already holds a link pointing out of the tree, planted by something other
        // than shroud -- shroud refuses link entries of its own. Normalising the entry name does not
        // follow links, so this is only caught by resolving the directories on the way down.
        Directory.CreateDirectory(ws.Path("outside"));
        Directory.CreateDirectory(ws.Path("restored"));

        if (!TryLinkDirectory(ws.Path("restored/sub"), ws.Path("outside")))
            return;

        var container = HostileArchive(entry => entry("sub/passwd", TarEntryType.RegularFile));
        ws.WriteBytes("evil.shroud", container);
        ws.WriteIdentity("bob", TestKeys.Bob);

        var decrypt = ws.Run("decrypt", "-i", ws.Path("evil.shroud"), "-o", ws.Path("restored"),
            "-k", ws.Path("bob.key"), "-f");

        Assert.Equal(Exit.BadContainer, decrypt.ExitCode);
        Assert.Contains("leaves the destination", decrypt.Stderr);
        Assert.False(File.Exists(ws.Path("outside/passwd")));
        Assert.Empty(ws.LeftoverPartials());
    }

    [Fact]
    public void ADestinationThatIsItselfALink_StillExtracts()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("bob", TestKeys.Bob);

        Directory.CreateDirectory(ws.Path("records"));
        File.WriteAllText(ws.Path("records/a.txt"), "content");
        Directory.CreateDirectory(ws.Path("real-destination"));

        if (!TryLinkDirectory(ws.Path("linked"), ws.Path("real-destination")))
            return;

        ws.Run("encrypt", "-i", ws.Path("records"), "-o", ws.Path("out.shroud"), "-r", ws.Path("bob.pub"));
        var decrypt = ws.Run("decrypt", "-i", ws.Path("out.shroud"), "-o", ws.Path("linked"), "-k", ws.Path("bob.key"));

        // Resolving links must refuse an escape without also refusing a destination the user
        // deliberately pointed somewhere else. This is the case that keeps the check honest.
        Assert.Equal(Exit.Ok, decrypt.ExitCode);
        Assert.Equal("content", File.ReadAllText(ws.Path("real-destination/a.txt")));
    }

    /// <summary>
    /// Links a directory, or reports that this machine will not allow it. Windows needs a privilege
    /// for symbolic links that an ordinary test run does not hold, so a junction stands in there:
    /// it is a reparse point too, and a write follows it exactly the same way.
    /// </summary>
    private static bool TryLinkDirectory(string link, string target)
    {
        try
        {
            Directory.CreateSymbolicLink(link, target);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            if (!OperatingSystem.IsWindows())
                return false;
        }

        using var mklink = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(
            "cmd.exe", $"/c mklink /J \"{link}\" \"{target}\"")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        });

        mklink?.WaitForExit();
        return Directory.Exists(link);
    }

    /// <summary>
    /// Builds a valid container whose plaintext is a tar with one chosen entry, flagged as an
    /// archive. The CLI only sets that flag for real directories, so this goes through the library.
    /// </summary>
    private static byte[] HostileArchive(Action<Action<string, TarEntryType>> build)
    {
        using var tar = new MemoryStream();

        using (var writer = new TarWriter(tar, TarEntryFormat.Pax, leaveOpen: true))
        {
            build((name, type) =>
            {
                var entry = new PaxTarEntry(type, name);

                if (type is TarEntryType.SymbolicLink)
                    entry.LinkName = "/etc/passwd";
                else
                    entry.DataStream = new MemoryStream("gotcha"u8.ToArray());

                writer.WriteEntry(entry);
            });
        }

        tar.Position = 0;

        using var container = new MemoryStream();
        ShroudFile.Encrypt(tar, container, TestKeys.Bob.GetPublicKey(), archive: true);
        return container.ToArray();
    }
}
