using Shroud.Core;

namespace Shroud.Cli.Tests;

public class CliKeyCommandTests
{
    [Fact]
    public void Keygen_WritesBothHalvesAndReportsTheFingerprint()
    {
        using var ws = new Workspace();

        var result = ws.Run("keygen", "--out", ws.Path("alice"), "--plaintext-key");

        Assert.Equal(Exit.Ok, result.ExitCode);
        Assert.True(ws.Exists("alice.key"));
        Assert.True(ws.Exists("alice.pub"));

        var fingerprint = ShroudPublicKey.Parse(ws.Text("alice.pub")).Fingerprint();

        Assert.Contains($"fingerprint: {fingerprint}", result.Stdout);
        Assert.Contains("shroud-recipient:v2:", ws.Text("alice.pub"));
        Assert.Contains("shroud-secret-key:v2:", ws.Text("alice.key"));

        // Both files carry a comment header naming the fingerprint, so a stray key file can be
        // identified without decoding it.
        Assert.Contains(fingerprint, ws.Text("alice.key"));
        Assert.StartsWith("#", ws.Text("alice.key"));

        // Writing an unprotected secret key is allowed but never silent.
        Assert.Contains("warning", result.Stderr);
    }

    [Fact]
    public void Keygen_ProtectsTheSecretKeyByDefaultAndTheKeyStillWorks()
    {
        using var ws = new Workspace();
        ws.WriteBytes("in.bin", [4, 5, 6]);

        var keygen = ws.Run("keygen", "--out", ws.Path("alice"));

        Assert.Equal(Exit.Ok, keygen.ExitCode);
        Assert.Contains("shroud-secret-key-encrypted:v2:", ws.Text("alice.key"));
        Assert.Contains("Argon2id", keygen.Stdout);
        Assert.DoesNotContain("warning", keygen.Stderr);

        var encrypt = ws.Run("encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"), "-r", ws.Path("alice.pub"));
        var decrypt = ws.Run("decrypt", "-i", ws.Path("out.shroud"), "-o", ws.Path("back.bin"), "-k", ws.Path("alice.key"));

        Assert.Equal(Exit.Ok, encrypt.ExitCode);
        Assert.Equal(Exit.Ok, decrypt.ExitCode);
        Assert.Equal(new byte[] { 4, 5, 6 }, ws.Bytes("back.bin"));
    }

    [Fact]
    public void ProtectedKey_WithTheWrongKeyPassphrase_IsRejected()
    {
        using var ws = new Workspace();
        ws.WriteBytes("in.bin", [4, 5, 6]);

        ws.Run("keygen", "--out", ws.Path("alice"));
        ws.Run("encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"), "-r", ws.Path("alice.pub"));

        var decrypt = ws.RunWith(
            Workspace.FilePassphrase, "not the key passphrase",
            "decrypt", "-i", ws.Path("out.shroud"), "-o", ws.Path("back.bin"), "-k", ws.Path("alice.key"));

        Assert.Equal(Exit.BadContainer, decrypt.ExitCode);
        Assert.Contains("Wrong passphrase for this key file", decrypt.Stderr);
        Assert.False(ws.Exists("back.bin"));
    }

    [Fact]
    public void Keygen_WillNotOverwriteAnExistingKeyWithoutForce()
    {
        using var ws = new Workspace();

        ws.Run("keygen", "--out", ws.Path("alice"), "--plaintext-key");
        var original = ws.Text("alice.key");

        var refused = ws.Run("keygen", "--out", ws.Path("alice"), "--plaintext-key");

        Assert.Equal(Exit.Usage, refused.ExitCode);
        Assert.Contains("--force", refused.Stderr);
        Assert.Equal(original, ws.Text("alice.key"));

        var forced = ws.Run("keygen", "--out", ws.Path("alice"), "--plaintext-key", "--force");

        Assert.Equal(Exit.Ok, forced.ExitCode);
        Assert.NotEqual(original, ws.Text("alice.key"));
    }

    [Fact]
    public void Passwd_RemovesProtectionAndTheKeyStillDecrypts()
    {
        using var ws = new Workspace();
        ws.WriteBytes("in.bin", [9, 9, 9]);

        ws.Run("keygen", "--out", ws.Path("alice"));
        ws.Run("encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"), "-r", ws.Path("alice.pub"));

        var passwd = ws.Run("passwd", "--key", ws.Path("alice.key"), "--plaintext-key");

        Assert.Equal(Exit.Ok, passwd.ExitCode);
        Assert.Contains("UNENCRYPTED", passwd.Stdout);
        Assert.Contains("shroud-secret-key:v2:", ws.Text("alice.key"));
        Assert.DoesNotContain("shroud-secret-key-encrypted:v2:", ws.Text("alice.key"));

        // The swap is atomic-ish: no leftover scratch file beside the original.
        Assert.False(ws.Exists("alice.key.new"));

        var decrypt = ws.RunWith(
            Workspace.FilePassphrase, keyPassphrase: null,
            "decrypt", "-i", ws.Path("out.shroud"), "-o", ws.Path("back.bin"), "-k", ws.Path("alice.key"));

        Assert.Equal(Exit.Ok, decrypt.ExitCode);
        Assert.Equal(new byte[] { 9, 9, 9 }, ws.Bytes("back.bin"));
    }

    [Fact]
    public void Passwd_WithoutAKey_IsAUsageError()
    {
        using var ws = new Workspace();

        var result = ws.Run("passwd");

        Assert.Equal(Exit.Usage, result.ExitCode);
        Assert.Contains("--key", result.Stderr);
    }

    [Fact]
    public void Fingerprint_AgreesBetweenTheTwoHalvesOfAnIdentity()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("alice", TestKeys.Alice);
        var expected = TestKeys.Alice.GetPublicKey().Fingerprint();

        var fromPublic = ws.Run("fingerprint", "--in", ws.Path("alice.pub"));
        var fromSecret = ws.Run("fingerprint", "--in", ws.Path("alice.key"));

        Assert.Equal(Exit.Ok, fromPublic.ExitCode);
        Assert.Equal(Exit.Ok, fromSecret.ExitCode);
        Assert.Equal(expected, fromPublic.Stdout.Trim());
        Assert.Equal(expected, fromSecret.Stdout.Trim());
    }

    [Fact]
    public void Fingerprint_ReadsAProtectedKeyFile()
    {
        using var ws = new Workspace();
        ws.Run("keygen", "--out", ws.Path("alice"));

        var fromPublic = ws.Run("fingerprint", "--in", ws.Path("alice.pub"));
        var fromSecret = ws.Run("fingerprint", "--in", ws.Path("alice.key"));

        Assert.Equal(Exit.Ok, fromSecret.ExitCode);
        Assert.Equal(fromPublic.Stdout.Trim(), fromSecret.Stdout.Trim());
    }

    [Fact]
    public void Fingerprint_WithoutInput_IsAUsageError()
    {
        using var ws = new Workspace();

        var result = ws.Run("fingerprint");

        Assert.Equal(Exit.Usage, result.ExitCode);
    }

    [Fact]
    public void Info_ReportsAnUnsignedRecipientContainer()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("bob", TestKeys.Bob);
        ws.WriteBytes("in.bin", [1, 2, 3]);

        ws.Run("encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"), "-r", ws.Path("bob.pub"));
        var info = ws.Run("info", "-i", ws.Path("out.shroud"));

        Assert.Equal(Exit.Ok, info.ExitCode);
        Assert.Contains("format:      Shroud v2", info.Stdout);
        Assert.Contains("mode:        recipient", info.Stdout);
        Assert.Contains("signed:      no", info.Stdout);
    }

    [Fact]
    public void Info_SaysAContainerIsSignedWithoutRevealingByWhom()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("alice", TestKeys.Alice);
        ws.WriteIdentity("bob", TestKeys.Bob);
        ws.WriteBytes("in.bin", [1, 2, 3]);

        ws.Run("encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"),
            "-r", ws.Path("bob.pub"), "-s", ws.Path("alice.key"));

        var info = ws.Run("info", "-i", ws.Path("out.shroud"));

        Assert.Contains("signed:      yes (ML-DSA-65)", info.Stdout);
        Assert.Contains("sender:      encrypted", info.Stdout);

        // The sending identity is inside the encrypted region. Reading the header must not leak it.
        Assert.DoesNotContain(TestKeys.Alice.GetPublicKey().Fingerprint(), info.Stdout);
    }

    [Fact]
    public void Info_ReportsThePassphraseModeCosts()
    {
        using var ws = new Workspace();
        ws.WriteBytes("in.bin", [1, 2, 3]);

        ws.Run("encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"), "-p");
        var info = ws.Run("info", "-i", ws.Path("out.shroud"));

        Assert.Equal(Exit.Ok, info.ExitCode);
        Assert.Contains("mode:        passphrase", info.Stdout);
        Assert.Contains("argon2id:    t=3 m=65536KiB p=4", info.Stdout);
    }
}
