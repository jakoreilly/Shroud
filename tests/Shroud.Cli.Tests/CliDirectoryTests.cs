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
