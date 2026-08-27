using Shroud.App;
using Shroud.Core;

namespace Shroud.App.Tests;

public sealed class IdentityServiceTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("shroud-app-tests-").FullName;

    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Fact]
    public void CreateDefault_WritesAProtectedIdentityAndReportsItsFingerprint()
    {
        var workspace = new ShroudWorkspace(Path.Combine(_root, "home"));

        var result = IdentityService.CreateDefault(workspace, "correct horse battery staple", force: false);

        Assert.True(result.Protected);
        Assert.Equal(workspace.IdentityKeyPath, result.SecretPath);
        Assert.Equal(workspace.IdentityPublicPath, result.PublicPath);
        Assert.True(File.Exists(result.SecretPath));
        Assert.Contains("shroud-secret-key-encrypted:v2:", File.ReadAllText(result.SecretPath));
        Assert.Contains(result.Fingerprint, File.ReadAllText(result.PublicPath));
    }

    [Fact]
    public void CreateDefault_Unprotected_WritesAPlaintextKey()
    {
        var workspace = new ShroudWorkspace(Path.Combine(_root, "home"));

        var result = IdentityService.CreateDefault(workspace, passphrase: null, force: false);

        Assert.False(result.Protected);
        Assert.Contains("shroud-secret-key:v2:", File.ReadAllText(result.SecretPath));
    }

    [Fact]
    public void CreateDefault_RefusesToOverwriteWithoutForce()
    {
        var workspace = new ShroudWorkspace(Path.Combine(_root, "home"));
        IdentityService.CreateDefault(workspace, passphrase: null, force: false);

        Assert.Throws<ShroudWorkspaceException>(() =>
            IdentityService.CreateDefault(workspace, passphrase: null, force: false));
    }

    [Fact]
    public void CreatedIdentity_CanRoundTripAFile()
    {
        var workspace = new ShroudWorkspace(Path.Combine(_root, "home"));
        var result = IdentityService.CreateDefault(workspace, passphrase: null, force: false);
        var secretKey = ShroudSecretKey.Parse(File.ReadAllText(result.SecretPath));

        using var input = new MemoryStream("hello"u8.ToArray());
        using var container = new MemoryStream();
        ShroudFile.Encrypt(input, container, secretKey.GetPublicKey());
        container.Position = 0;

        using var output = new MemoryStream();
        ShroudFile.Decrypt(container, output, secretKey);

        Assert.Equal("hello"u8.ToArray(), output.ToArray());
    }
}
