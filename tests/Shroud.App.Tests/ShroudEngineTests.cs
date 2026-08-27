using Shroud.App;
using Shroud.Core;

namespace Shroud.App.Tests;

public sealed class ShroudEngineTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("shroud-app-tests-").FullName;

    public void Dispose() => Directory.Delete(_root, recursive: true);

    private string Path(string name) => System.IO.Path.Combine(_root, name);

    [Fact]
    public void Inspect_ReportsNonContainerForOrdinaryFiles()
    {
        var engine = new ShroudEngine(new ShroudWorkspace(Path("home")));
        var plain = Path("plain.txt");
        File.WriteAllText(plain, "not a container");

        var summary = engine.Inspect(plain);

        Assert.False(summary.IsContainer);
    }

    [Fact]
    public void EncryptThenDecrypt_ToARecipient_RoundTrips()
    {
        var workspace = new ShroudWorkspace(Path("home"));
        var engine = new ShroudEngine(workspace);

        var alice = ShroudSecretKey.Generate();
        var bob = ShroudSecretKey.Generate();

        var plaintext = Path("in.txt");
        File.WriteAllText(plaintext, "hello from the engine");
        var container = Path("out.shroud");
        var roundTripped = Path("roundtrip.txt");

        engine.Encrypt(
            new EncryptRequest(plaintext, container, bob.GetPublicKey(), Passphrase: null, alice, Force: false),
            progress: null,
            CancellationToken.None);

        var summary = engine.Inspect(container);
        Assert.True(summary.IsContainer);
        Assert.True(summary.IsSigned);

        var report = engine.Decrypt(
            new DecryptRequest(
                container, roundTripped, bob, Passphrase: null, ExpectedSender: alice.GetPublicKey(),
                RequireSigned: false, Extract: true, Force: false),
            progress: null,
            CancellationToken.None);

        Assert.Equal(SignatureStanding.ExpectedSender, report.Standing);
        Assert.Equal("hello from the engine", File.ReadAllText(roundTripped));
    }

    [Fact]
    public void EncryptThenDecrypt_ADirectory_ExtractsBackToATree()
    {
        var workspace = new ShroudWorkspace(Path("home"));
        var engine = new ShroudEngine(workspace);
        var bob = ShroudSecretKey.Generate();

        var sourceDir = Path("records");
        Directory.CreateDirectory(sourceDir);
        File.WriteAllText(System.IO.Path.Combine(sourceDir, "a.txt"), "a");

        var container = Path("records.shroud");
        var destDir = Path("restored");

        engine.Encrypt(
            new EncryptRequest(sourceDir, container, bob.GetPublicKey(), Passphrase: null, Sender: null, Force: false),
            progress: null,
            CancellationToken.None);

        engine.Decrypt(
            new DecryptRequest(container, destDir, bob, Passphrase: null, ExpectedSender: null, RequireSigned: false, Extract: true, Force: false),
            progress: null,
            CancellationToken.None);

        Assert.Equal("a", File.ReadAllText(System.IO.Path.Combine(destDir, "a.txt")));
    }

    [Fact]
    public void Encrypt_RefusesAnExistingOutputWithoutForce()
    {
        var engine = new ShroudEngine(new ShroudWorkspace(Path("home")));
        var bob = ShroudSecretKey.Generate();

        var plaintext = Path("in.txt");
        File.WriteAllText(plaintext, "data");
        var container = Path("out.shroud");
        File.WriteAllText(container, "already here");

        Assert.Throws<ShroudWorkspaceException>(() => engine.Encrypt(
            new EncryptRequest(plaintext, container, bob.GetPublicKey(), Passphrase: null, Sender: null, Force: false),
            progress: null,
            CancellationToken.None));
    }

    [Fact]
    public void Decrypt_ThrowsAndLeavesNoOutput_WhenCancelledMidway()
    {
        var workspace = new ShroudWorkspace(Path("home"));
        var engine = new ShroudEngine(workspace);
        var bob = ShroudSecretKey.Generate();

        var plaintext = Path("in.bin");
        File.WriteAllBytes(plaintext, new byte[5 * 1024 * 1024]);
        var container = Path("out.shroud");
        var destination = Path("out.bin");

        engine.Encrypt(
            new EncryptRequest(plaintext, container, bob.GetPublicKey(), Passphrase: null, Sender: null, Force: false),
            progress: null,
            CancellationToken.None);

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        Assert.ThrowsAny<OperationCanceledException>(() => engine.Decrypt(
            new DecryptRequest(container, destination, bob, Passphrase: null, ExpectedSender: null, RequireSigned: false, Extract: false, Force: false),
            progress: null,
            cts.Token));

        Assert.False(File.Exists(destination));
    }
}
