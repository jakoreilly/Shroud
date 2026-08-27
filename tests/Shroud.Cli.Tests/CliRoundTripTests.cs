using System.Security.Cryptography;

namespace Shroud.Cli.Tests;

public class CliRoundTripTests
{
    [Fact]
    public void RecipientMode_RoundTripsAndWarnsThatNothingIsSigned()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("bob", TestKeys.Bob);
        var plaintext = RandomNumberGenerator.GetBytes(50_000);
        ws.WriteBytes("in.bin", plaintext);

        var encrypt = ws.Run("encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"), "-r", ws.Path("bob.pub"));
        var decrypt = ws.Run("decrypt", "-i", ws.Path("out.shroud"), "-o", ws.Path("back.bin"), "-k", ws.Path("bob.key"));

        Assert.Equal(Exit.Ok, encrypt.ExitCode);
        Assert.Equal(Exit.Ok, decrypt.ExitCode);
        Assert.Equal(plaintext, ws.Bytes("back.bin"));
        Assert.Contains("UNSIGNED", decrypt.Stderr);
    }

    [Fact]
    public void SignedContainer_VerifiesAgainstTheNamedSender()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("alice", TestKeys.Alice);
        ws.WriteIdentity("bob", TestKeys.Bob);
        var plaintext = RandomNumberGenerator.GetBytes(9000);
        ws.WriteBytes("in.bin", plaintext);

        var encrypt = ws.Run(
            "encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"),
            "-r", ws.Path("bob.pub"), "-s", ws.Path("alice.key"));

        var decrypt = ws.Run(
            "decrypt", "-i", ws.Path("out.shroud"), "-o", ws.Path("back.bin"),
            "-k", ws.Path("bob.key"), "--sender", ws.Path("alice.pub"));

        Assert.Equal(Exit.Ok, encrypt.ExitCode);
        Assert.Contains(TestKeys.Alice.GetPublicKey().Fingerprint(), encrypt.Stderr);

        Assert.Equal(Exit.Ok, decrypt.ExitCode);
        Assert.Equal(plaintext, ws.Bytes("back.bin"));
        Assert.Contains("signature OK", decrypt.Stderr);
        Assert.Contains(TestKeys.Alice.GetPublicKey().Fingerprint(), decrypt.Stderr);
    }

    [Fact]
    public void SignedContainer_WithoutASenderToCheckAgainst_SaysTheIdentityIsUnchecked()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("alice", TestKeys.Alice);
        ws.WriteIdentity("bob", TestKeys.Bob);
        ws.WriteBytes("in.bin", [1, 2, 3]);

        ws.Run("encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"),
            "-r", ws.Path("bob.pub"), "-s", ws.Path("alice.key"));

        var decrypt = ws.Run("decrypt", "-i", ws.Path("out.shroud"), "-o", ws.Path("back.bin"), "-k", ws.Path("bob.key"));

        // A valid signature from an unchecked key is not evidence of origin, and must not be
        // reported as though it were.
        Assert.Equal(Exit.Ok, decrypt.ExitCode);
        Assert.Contains("NOT checked", decrypt.Stderr);
    }

    [Fact]
    public void WrongExpectedSender_ExitsThreeAndWritesNothing()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("alice", TestKeys.Alice);
        ws.WriteIdentity("bob", TestKeys.Bob);
        ws.WriteBytes("in.bin", RandomNumberGenerator.GetBytes(9000));

        ws.Run("encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"),
            "-r", ws.Path("bob.pub"), "-s", ws.Path("alice.key"));

        var decrypt = ws.Run(
            "decrypt", "-i", ws.Path("out.shroud"), "-o", ws.Path("back.bin"),
            "-k", ws.Path("bob.key"), "--sender", ws.Path("bob.pub"));

        Assert.Equal(Exit.Signature, decrypt.ExitCode);
        Assert.Contains("was expected", decrypt.Stderr);
        Assert.False(ws.Exists("back.bin"));
        Assert.Empty(ws.LeftoverPartials());
    }

    [Fact]
    public void UnsignedContainer_UnderRequireSigned_ExitsThree()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("bob", TestKeys.Bob);
        ws.WriteBytes("in.bin", [1, 2, 3]);

        ws.Run("encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"), "-r", ws.Path("bob.pub"));

        var decrypt = ws.Run(
            "decrypt", "-i", ws.Path("out.shroud"), "-o", ws.Path("back.bin"),
            "-k", ws.Path("bob.key"), "--require-signed");

        Assert.Equal(Exit.Signature, decrypt.ExitCode);
        Assert.False(ws.Exists("back.bin"));
    }

    [Fact]
    public void UnsignedContainer_WithAnExpectedSender_ExitsThree()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("alice", TestKeys.Alice);
        ws.WriteIdentity("bob", TestKeys.Bob);
        ws.WriteBytes("in.bin", [1, 2, 3]);

        ws.Run("encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"), "-r", ws.Path("bob.pub"));

        var decrypt = ws.Run(
            "decrypt", "-i", ws.Path("out.shroud"), "-o", ws.Path("back.bin"),
            "-k", ws.Path("bob.key"), "--sender", ws.Path("alice.pub"));

        // --sender implies --require-signed: asking who sent it must not silently accept
        // a container that nobody signed.
        Assert.Equal(Exit.Signature, decrypt.ExitCode);
        Assert.False(ws.Exists("back.bin"));
    }

    [Fact]
    public void WrongKey_ExitsTwoAndLeavesNoOutput()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("alice", TestKeys.Alice);
        ws.WriteIdentity("bob", TestKeys.Bob);
        ws.WriteBytes("in.bin", RandomNumberGenerator.GetBytes(9000));

        ws.Run("encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"), "-r", ws.Path("bob.pub"));

        var decrypt = ws.Run("decrypt", "-i", ws.Path("out.shroud"), "-o", ws.Path("back.bin"), "-k", ws.Path("alice.key"));

        Assert.Equal(Exit.BadContainer, decrypt.ExitCode);
        Assert.False(ws.Exists("back.bin"));
        Assert.Empty(ws.LeftoverPartials());
    }

    [Fact]
    public void TamperedContainer_ExitsTwoAndLeavesNoPartialPlaintext()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("bob", TestKeys.Bob);

        // Several chunks, so the corruption lands well past the first one and the CLI has already
        // written a plaintext prefix to its staging file by the time authentication fails.
        ws.WriteBytes("in.bin", RandomNumberGenerator.GetBytes(3 * 1024 * 1024));
        ws.Run("encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"), "-r", ws.Path("bob.pub"));
        ws.Corrupt("out.shroud", 2 * 1024 * 1024);

        var decrypt = ws.Run("decrypt", "-i", ws.Path("out.shroud"), "-o", ws.Path("back.bin"), "-k", ws.Path("bob.key"));

        Assert.Equal(Exit.BadContainer, decrypt.ExitCode);
        Assert.False(ws.Exists("back.bin"));
        Assert.Empty(ws.LeftoverPartials());
    }

    [Fact]
    public void PassphraseMode_RoundTrips()
    {
        using var ws = new Workspace();
        var plaintext = RandomNumberGenerator.GetBytes(20_000);
        ws.WriteBytes("in.bin", plaintext);

        var encrypt = ws.Run("encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"), "-p");
        var decrypt = ws.Run("decrypt", "-i", ws.Path("out.shroud"), "-o", ws.Path("back.bin"), "-p");

        Assert.Equal(Exit.Ok, encrypt.ExitCode);
        Assert.Equal(Exit.Ok, decrypt.ExitCode);
        Assert.Equal(plaintext, ws.Bytes("back.bin"));
    }

    [Fact]
    public void PassphraseMode_CanBeSignedAndVerified()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("alice", TestKeys.Alice);
        ws.WriteBytes("in.bin", [7, 7, 7]);

        var encrypt = ws.Run("encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"),
            "-p", "-s", ws.Path("alice.key"));

        var decrypt = ws.Run("decrypt", "-i", ws.Path("out.shroud"), "-o", ws.Path("back.bin"),
            "-p", "--sender", ws.Path("alice.pub"));

        Assert.Equal(Exit.Ok, encrypt.ExitCode);
        Assert.Equal(Exit.Ok, decrypt.ExitCode);
        Assert.Equal(new byte[] { 7, 7, 7 }, ws.Bytes("back.bin"));
        Assert.Contains("signature OK", decrypt.Stderr);
    }

    [Fact]
    public void WrongPassphrase_ExitsTwo()
    {
        using var ws = new Workspace();
        ws.WriteBytes("in.bin", [1, 2, 3]);

        ws.Run("encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"), "-p");

        var decrypt = ws.RunWith(
            "not the passphrase", Workspace.KeyPassphrase,
            "decrypt", "-i", ws.Path("out.shroud"), "-o", ws.Path("back.bin"), "-p");

        Assert.Equal(Exit.BadContainer, decrypt.ExitCode);
        Assert.False(ws.Exists("back.bin"));
    }

    [Fact]
    public void PassphraseFile_IsAcceptedInsteadOfTheEnvironment()
    {
        using var ws = new Workspace();
        ws.WriteBytes("in.bin", [1, 2, 3]);

        // Trailing newline included on purpose: an editor-written passphrase file must work.
        ws.WriteText("pass.txt", "a passphrase from a file\n");

        var encrypt = ws.RunWith(null, null,
            "encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"), "--passphrase-file", ws.Path("pass.txt"));

        var decrypt = ws.RunWith(null, null,
            "decrypt", "-i", ws.Path("out.shroud"), "-o", ws.Path("back.bin"), "--passphrase-file", ws.Path("pass.txt"));

        Assert.Equal(Exit.Ok, encrypt.ExitCode);
        Assert.Equal(Exit.Ok, decrypt.ExitCode);
        Assert.Equal(new byte[] { 1, 2, 3 }, ws.Bytes("back.bin"));
    }

    [Fact]
    public void EmptyPassphraseFile_IsAUsageError()
    {
        using var ws = new Workspace();
        ws.WriteBytes("in.bin", [1, 2, 3]);
        ws.WriteText("pass.txt", "\n");

        var result = ws.RunWith(null, null,
            "encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"), "--passphrase-file", ws.Path("pass.txt"));

        Assert.Equal(Exit.Usage, result.ExitCode);
        Assert.Contains("is empty", result.Stderr);
    }

    [Fact]
    public void ExistingOutput_IsNotOverwrittenWithoutForce()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("bob", TestKeys.Bob);
        ws.WriteBytes("in.bin", [1, 2, 3]);
        ws.WriteText("out.shroud", "do not clobber me");

        var refused = ws.Run("encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"), "-r", ws.Path("bob.pub"));

        Assert.Equal(Exit.Usage, refused.ExitCode);
        Assert.Contains("--force", refused.Stderr);
        Assert.Equal("do not clobber me", ws.Text("out.shroud"));

        var forced = ws.Run("encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"), "-r", ws.Path("bob.pub"), "-f");

        Assert.Equal(Exit.Ok, forced.ExitCode);
        Assert.NotEqual("do not clobber me", ws.Text("out.shroud"));
    }

    [Fact]
    public void ChunkSizeOption_IsHonouredAndRecorded()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("bob", TestKeys.Bob);
        ws.WriteBytes("in.bin", RandomNumberGenerator.GetBytes(20_000));

        var encrypt = ws.Run("encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"),
            "-r", ws.Path("bob.pub"), "--chunk-size-log", "12");

        var info = ws.Run("info", "-i", ws.Path("out.shroud"));

        Assert.Equal(Exit.Ok, encrypt.ExitCode);
        Assert.Contains("chunk size:  4 KiB", info.Stdout);
    }

    [Fact]
    public void EmptyFile_RoundTrips()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("bob", TestKeys.Bob);
        ws.WriteBytes("in.bin", []);

        ws.Run("encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"), "-r", ws.Path("bob.pub"));
        var decrypt = ws.Run("decrypt", "-i", ws.Path("out.shroud"), "-o", ws.Path("back.bin"), "-k", ws.Path("bob.key"));

        Assert.Equal(Exit.Ok, decrypt.ExitCode);
        Assert.Empty(ws.Bytes("back.bin"));
    }
}
