namespace Shroud.Cli.Tests;

/// <summary>
/// Contacts exist so the fingerprint comparison happens once, deliberately, instead of being
/// retyped or skipped on every file. The tests that matter most here are the ones about what
/// happens when the fingerprint does not match.
/// </summary>
public class CliContactsTests
{
    private static string Alice => TestKeys.Alice.GetPublicKey().Fingerprint();

    [Fact]
    public void AddingAContact_RequiresTheFingerprintToMatch()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("alice", TestKeys.Alice);

        var result = ws.Run("contacts", "add", "--in", ws.Path("alice.pub"), "--name", "alice",
            "--fingerprint", Alice);

        Assert.Equal(Exit.Ok, result.ExitCode);
        Assert.Contains(Alice, result.Stdout);
        Assert.Contains("alice", ws.Run("contacts", "list").Stdout);
    }

    [Fact]
    public void AddingAContact_WithTheWrongFingerprint_IsRefused()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("alice", TestKeys.Alice);

        var result = ws.Run("contacts", "add", "--in", ws.Path("alice.pub"), "--name", "alice",
            "--fingerprint", "0000000000000000");

        // This is the whole point of the command: a mismatch means the key you received is not
        // the key they sent, and the tool must not help you past that.
        Assert.Equal(Exit.Usage, result.ExitCode);
        Assert.Contains("Fingerprint mismatch", result.Stderr);
        Assert.Contains("No contacts yet", ws.Run("contacts", "list").Stdout);
    }

    [Fact]
    public void AddingAContact_WithoutAFingerprint_IsRefused()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("alice", TestKeys.Alice);

        var result = ws.Run("contacts", "add", "--in", ws.Path("alice.pub"), "--name", "alice");

        Assert.Equal(Exit.Usage, result.ExitCode);
        Assert.Contains("--fingerprint", result.Stderr);
    }

    [Theory]
    [InlineData("../escape")]
    [InlineData("a/b")]
    [InlineData("..")]
    [InlineData("with space")]
    public void ContactNamesThatCouldEscapeTheStore_AreRefused(string name)
    {
        using var ws = new Workspace();
        ws.WriteIdentity("alice", TestKeys.Alice);

        var result = ws.Run("contacts", "add", "--in", ws.Path("alice.pub"), "--name", name,
            "--fingerprint", Alice);

        // The name becomes a filename, so it is validated rather than trusted.
        Assert.Equal(Exit.Usage, result.ExitCode);
        Assert.Contains("not a usable contact name", result.Stderr);
    }

    [Fact]
    public void ContactsCanBeUsedByNameForRecipientAndSender()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("alice", TestKeys.Alice);
        ws.WriteIdentity("bob", TestKeys.Bob);
        ws.WriteBytes("in.bin", [1, 2, 3]);

        ws.Run("contacts", "add", "--in", ws.Path("alice.pub"), "--name", "alice", "--fingerprint", Alice);
        ws.Run("contacts", "add", "--in", ws.Path("bob.pub"), "--name", "bob",
            "--fingerprint", TestKeys.Bob.GetPublicKey().Fingerprint());

        var encrypt = ws.Run("encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"),
            "-r", "bob", "-s", ws.Path("alice.key"));

        var decrypt = ws.Run("decrypt", "-i", ws.Path("out.shroud"), "-o", ws.Path("back.bin"),
            "-k", ws.Path("bob.key"), "--sender", "alice");

        Assert.Equal(Exit.Ok, encrypt.ExitCode);
        Assert.Equal(Exit.Ok, decrypt.ExitCode);
        Assert.Equal(new byte[] { 1, 2, 3 }, ws.Bytes("back.bin"));

        // A name is never shown on its own: the fingerprint travels with it.
        Assert.Contains($"bob ({TestKeys.Bob.GetPublicKey().Fingerprint()})", encrypt.Stderr);
        Assert.Contains($"alice ({Alice})", decrypt.Stderr);
    }

    [Fact]
    public void AKnownSignerIsNamedWithoutBeingAsked()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("alice", TestKeys.Alice);
        ws.WriteIdentity("bob", TestKeys.Bob);
        ws.WriteBytes("in.bin", [1, 2, 3]);

        ws.Run("contacts", "add", "--in", ws.Path("alice.pub"), "--name", "alice", "--fingerprint", Alice);
        ws.Run("encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"),
            "-r", ws.Path("bob.pub"), "-s", ws.Path("alice.key"));

        var decrypt = ws.Run("decrypt", "-i", ws.Path("out.shroud"), "-o", ws.Path("back.bin"), "-k", ws.Path("bob.key"));

        // No --sender given, but the signing key is one whose fingerprint was checked when the
        // contact was added, so identifying it is as strong as naming it.
        Assert.Equal(Exit.Ok, decrypt.ExitCode);
        Assert.Contains("verified contact alice", decrypt.Stderr);
        Assert.DoesNotContain("NOT checked", decrypt.Stderr);
    }

    [Fact]
    public void AnUnknownSignerIsStillReportedAsUnknown()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("alice", TestKeys.Alice);
        ws.WriteIdentity("bob", TestKeys.Bob);
        ws.WriteBytes("in.bin", [1, 2, 3]);

        ws.Run("encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"),
            "-r", ws.Path("bob.pub"), "-s", ws.Path("alice.key"));

        var decrypt = ws.Run("decrypt", "-i", ws.Path("out.shroud"), "-o", ws.Path("back.bin"), "-k", ws.Path("bob.key"));

        Assert.Equal(Exit.Ok, decrypt.ExitCode);
        Assert.Contains("NOT checked", decrypt.Stderr);
        Assert.Contains("not one of your contacts", decrypt.Stderr);
    }

    [Fact]
    public void RemovingAContact_TakesItOutOfTheStore()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("alice", TestKeys.Alice);

        ws.Run("contacts", "add", "--in", ws.Path("alice.pub"), "--name", "alice", "--fingerprint", Alice);
        var removed = ws.Run("contacts", "remove", "--name", "alice");

        Assert.Equal(Exit.Ok, removed.ExitCode);
        Assert.Contains("No contacts yet", ws.Run("contacts", "list").Stdout);
        Assert.Equal(Exit.Usage, ws.Run("contacts", "remove", "--name", "alice").ExitCode);
    }

    [Fact]
    public void UnknownContactName_IsAUsageError()
    {
        using var ws = new Workspace();
        ws.WriteBytes("in.bin", [1]);

        var result = ws.Run("encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"), "-r", "nobody");

        Assert.Equal(Exit.Usage, result.ExitCode);
        Assert.Contains("No file or contact named", result.Stderr);
    }

    [Fact]
    public void UnknownContactsSubcommand_IsAUsageError()
    {
        using var ws = new Workspace();

        var result = ws.Run("contacts", "frobnicate");

        Assert.Equal(Exit.Usage, result.ExitCode);
        Assert.Contains("Unknown contacts subcommand", result.Stderr);
    }
}
