using System.Security.Cryptography;

namespace Shroud.Cli.Tests;

/// <summary>
/// `verify` answers "is this intact and from who I think" without putting the plaintext on disk.
/// It still has to decrypt — the signature lives inside the encrypted region — so the thing worth
/// testing is that nothing is written.
/// </summary>
public class CliVerifyTests
{
    [Fact]
    public void Verify_AcceptsAGoodContainerAndWritesNothing()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("alice", TestKeys.Alice);
        ws.WriteIdentity("bob", TestKeys.Bob);
        ws.WriteBytes("in.bin", RandomNumberGenerator.GetBytes(9000));

        ws.Run("encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"),
            "-r", ws.Path("bob.pub"), "-s", ws.Path("alice.key"));

        var before = Directory.GetFiles(ws.Path("."));
        var verify = ws.Run("verify", "-i", ws.Path("out.shroud"), "-k", ws.Path("bob.key"),
            "--sender", ws.Path("alice.pub"));

        Assert.Equal(Exit.Ok, verify.ExitCode);
        Assert.Contains("intact", verify.Stdout);
        Assert.Contains("signature OK", verify.Stderr);
        Assert.Equal(before.Length, Directory.GetFiles(ws.Path(".")).Length);
        Assert.Empty(ws.LeftoverPartials());
    }

    [Fact]
    public void Verify_RejectsAContainerFromTheWrongSender()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("alice", TestKeys.Alice);
        ws.WriteIdentity("bob", TestKeys.Bob);
        ws.WriteBytes("in.bin", [1, 2, 3]);

        ws.Run("encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"),
            "-r", ws.Path("bob.pub"), "-s", ws.Path("alice.key"));

        var verify = ws.Run("verify", "-i", ws.Path("out.shroud"), "-k", ws.Path("bob.key"),
            "--sender", ws.Path("bob.pub"));

        Assert.Equal(Exit.Signature, verify.ExitCode);
        Assert.Contains("was expected", verify.Stderr);
    }

    [Fact]
    public void Verify_DetectsATamperedContainer()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("bob", TestKeys.Bob);
        ws.WriteBytes("in.bin", RandomNumberGenerator.GetBytes(20_000));

        ws.Run("encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"), "-r", ws.Path("bob.pub"));
        ws.Corrupt("out.shroud", 8000);

        var verify = ws.Run("verify", "-i", ws.Path("out.shroud"), "-k", ws.Path("bob.key"));

        Assert.Equal(Exit.BadContainer, verify.ExitCode);
        Assert.Contains("Authentication failed", verify.Stderr);
    }

    [Fact]
    public void Verify_WorksInPassphraseMode()
    {
        using var ws = new Workspace();
        ws.WriteBytes("in.bin", [1, 2, 3]);

        ws.Run("encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"), "-p");

        var verify = ws.Run("verify", "-i", ws.Path("out.shroud"), "-p");

        Assert.Equal(Exit.Ok, verify.ExitCode);
        Assert.Contains("UNSIGNED", verify.Stderr);
    }

    [Fact]
    public void Verify_ReportsWhetherTheContentIsAnArchive()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("bob", TestKeys.Bob);
        Directory.CreateDirectory(ws.Path("records"));
        File.WriteAllText(ws.Path("records/a.txt"), "x");

        ws.Run("encrypt", "-i", ws.Path("records"), "-o", ws.Path("out.shroud"), "-r", ws.Path("bob.pub"));
        var verify = ws.Run("verify", "-i", ws.Path("out.shroud"), "-k", ws.Path("bob.key"));

        Assert.Equal(Exit.Ok, verify.ExitCode);
        Assert.Contains("directory archive", verify.Stdout);
    }

    [Fact]
    public void Verify_NeedsAKeyOrPassphrase()
    {
        using var ws = new Workspace();
        ws.WriteBytes("out.shroud", [1]);

        var verify = ws.Run("verify", "-i", ws.Path("out.shroud"));

        Assert.Equal(Exit.Usage, verify.ExitCode);
        Assert.Contains("--key", verify.Stderr);
    }
}

/// <summary>The default identity is what makes signing the normal case rather than a flag.</summary>
public class CliIdentityTests
{
    [Fact]
    public void EncryptSignsWithTheDefaultIdentityWithoutBeingAsked()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("bob", TestKeys.Bob);
        ws.WriteBytes("in.bin", [1, 2, 3]);

        ws.Run("keygen", "--plaintext-key");
        var mine = File.ReadAllText(Path.Combine(ws.Home, "identity.pub"));
        var fingerprint = Shroud.Core.ShroudPublicKey.Parse(mine).Fingerprint();

        var encrypt = ws.Run("encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"), "-r", ws.Path("bob.pub"));
        var info = ws.Run("info", "-i", ws.Path("out.shroud"));

        Assert.Equal(Exit.Ok, encrypt.ExitCode);
        Assert.Contains($"signing as {fingerprint}", encrypt.Stderr);
        Assert.Contains("signed:      yes", info.Stdout);
    }

    [Fact]
    public void NoSign_SuppressesTheDefaultIdentity()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("bob", TestKeys.Bob);
        ws.WriteBytes("in.bin", [1, 2, 3]);

        ws.Run("keygen", "--plaintext-key");
        var encrypt = ws.Run("encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"),
            "-r", ws.Path("bob.pub"), "--no-sign");

        Assert.Equal(Exit.Ok, encrypt.ExitCode);
        Assert.DoesNotContain("signing as", encrypt.Stderr);
        Assert.Contains("signed:      no", ws.Run("info", "-i", ws.Path("out.shroud")).Stdout);
    }

    [Fact]
    public void SignAndNoSignTogether_IsAUsageError()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("alice", TestKeys.Alice);
        ws.WriteIdentity("bob", TestKeys.Bob);
        ws.WriteBytes("in.bin", [1]);

        var result = ws.Run("encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"),
            "-r", ws.Path("bob.pub"), "-s", ws.Path("alice.key"), "--no-sign");

        Assert.Equal(Exit.Usage, result.ExitCode);
        Assert.Contains("not both", result.Stderr);
    }

    [Fact]
    public void NoIdentityMeansNoSignature()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("bob", TestKeys.Bob);
        ws.WriteBytes("in.bin", [1, 2, 3]);

        var encrypt = ws.Run("encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"), "-r", ws.Path("bob.pub"));

        Assert.Equal(Exit.Ok, encrypt.ExitCode);
        Assert.Contains("signed:      no", ws.Run("info", "-i", ws.Path("out.shroud")).Stdout);
    }
}
