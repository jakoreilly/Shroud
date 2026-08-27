namespace Shroud.Cli.Tests;

/// <summary>
/// Bad input must produce the documented exit code and a one-line message. Anything the command
/// fails to handle escapes as an exception and fails these tests, which is how an unhandled
/// stack trace gets caught.
/// </summary>
public class CliOptionTests
{
    [Theory]
    [InlineData("11")]   // below the minimum
    [InlineData("27")]   // above the maximum
    [InlineData("30")]
    [InlineData("0")]
    public void OutOfRangeChunkSize_IsAUsageError(string log)
    {
        using var ws = new Workspace();
        ws.WriteIdentity("bob", TestKeys.Bob);
        ws.WriteBytes("in.bin", [1, 2, 3]);

        var result = ws.Run("encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"),
            "-r", ws.Path("bob.pub"), "--chunk-size-log", log);

        Assert.Equal(Exit.Usage, result.ExitCode);
        Assert.Contains("must be between 12 and 26", result.Stderr);
        Assert.False(ws.Exists("out.shroud"));
        Assert.Empty(ws.LeftoverPartials());
    }

    [Theory]
    [InlineData("twenty")]
    [InlineData("-1")]
    [InlineData("999")]
    public void NonNumericChunkSize_IsAUsageError(string log)
    {
        using var ws = new Workspace();
        ws.WriteIdentity("bob", TestKeys.Bob);
        ws.WriteBytes("in.bin", [1, 2, 3]);

        var result = ws.Run("encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"),
            "-r", ws.Path("bob.pub"), "--chunk-size-log", log);

        Assert.Equal(Exit.Usage, result.ExitCode);
        Assert.Contains("--chunk-size-log", result.Stderr);
    }

    [Fact]
    public void DirectoryGivenAsDecryptInput_IsAnIoError()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("bob", TestKeys.Bob);
        Directory.CreateDirectory(ws.Path("a-directory"));

        // encrypt treats a directory as something to archive; decrypt has no such reading of it,
        // so this ends up opening a directory as a file. That raises UnauthorizedAccessException,
        // which is not an IOException and needs its own catch.
        var result = ws.Run("decrypt", "-i", ws.Path("a-directory"), "-o", ws.Path("out.bin"), "-k", ws.Path("bob.key"));

        Assert.Equal(Exit.Io, result.ExitCode);
        Assert.Empty(ws.LeftoverPartials());
    }

    [Fact]
    public void MissingInputFile_IsAnIoError()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("bob", TestKeys.Bob);

        var result = ws.Run("encrypt", "-i", ws.Path("nope.bin"), "-o", ws.Path("out.shroud"), "-r", ws.Path("bob.pub"));

        Assert.Equal(Exit.Io, result.ExitCode);
        Assert.Empty(ws.LeftoverPartials());
    }

    [Fact]
    public void EmptyOptionValue_IsAUsageError()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("bob", TestKeys.Bob);

        // An empty path reaches the file APIs as an ArgumentException rather than a missing file.
        var result = ws.Run("encrypt", "-i", "", "-o", ws.Path("out.shroud"), "-r", ws.Path("bob.pub"));

        Assert.Equal(Exit.Usage, result.ExitCode);
        Assert.Contains("non-empty", result.Stderr);
    }

    [Fact]
    public void OptionWithoutItsValue_IsAUsageError()
    {
        using var ws = new Workspace();

        var result = ws.Run("encrypt", "-i");

        Assert.Equal(Exit.Usage, result.ExitCode);
        Assert.Contains("needs a value", result.Stderr);
    }

    [Fact]
    public void UnknownOption_IsAUsageError()
    {
        using var ws = new Workspace();

        var result = ws.Run("encrypt", "--turbo");

        Assert.Equal(Exit.Usage, result.ExitCode);
        Assert.Contains("Unknown option", result.Stderr);
    }

    [Fact]
    public void UnknownCommand_IsAUsageError()
    {
        using var ws = new Workspace();

        var result = ws.Run("encryptify", "-i", "a", "-o", "b");

        Assert.Equal(Exit.Usage, result.ExitCode);
        Assert.Contains("Unknown command", result.Stderr);
    }

    [Fact]
    public void NoArguments_PrintsUsageAndFails()
    {
        using var ws = new Workspace();

        var result = ws.Run();

        Assert.Equal(Exit.Usage, result.ExitCode);
        Assert.Contains("USAGE", result.Stdout);
    }

    [Theory]
    [InlineData("--help")]
    [InlineData("-h")]
    [InlineData("help")]
    public void HelpSucceedsAndDocumentsTheExitCodes(string flag)
    {
        using var ws = new Workspace();

        var result = ws.Run(flag);

        Assert.Equal(Exit.Ok, result.ExitCode);
        Assert.Contains("EXIT CODES", result.Stdout);
        Assert.Contains("--sender", result.Stdout);
    }

    [Fact]
    public void RecipientAndPassphraseTogether_IsAUsageError()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("bob", TestKeys.Bob);
        ws.WriteBytes("in.bin", [1]);

        var result = ws.Run("encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"),
            "-r", ws.Path("bob.pub"), "-p");

        Assert.Equal(Exit.Usage, result.ExitCode);
        Assert.Contains("not both", result.Stderr);
    }

    [Fact]
    public void KeyAndPassphraseTogether_IsAUsageError()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("bob", TestKeys.Bob);

        var result = ws.Run("decrypt", "-i", ws.Path("x.shroud"), "-o", ws.Path("x.bin"),
            "-k", ws.Path("bob.key"), "-p");

        Assert.Equal(Exit.Usage, result.ExitCode);
        Assert.Contains("not both", result.Stderr);
    }

    [Fact]
    public void EncryptWithNeitherRecipientNorPassphrase_IsAUsageError()
    {
        using var ws = new Workspace();
        ws.WriteBytes("in.bin", [1]);

        var result = ws.Run("encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"));

        Assert.Equal(Exit.Usage, result.ExitCode);
        Assert.Contains("--recipient", result.Stderr);
    }

    [Fact]
    public void DecryptWithNeitherKeyNorPassphrase_IsAUsageError()
    {
        using var ws = new Workspace();

        var result = ws.Run("decrypt", "-i", ws.Path("in.shroud"), "-o", ws.Path("out.bin"));

        Assert.Equal(Exit.Usage, result.ExitCode);
        Assert.Contains("--key", result.Stderr);
    }

    [Fact]
    public void MissingOutput_IsAUsageError()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("bob", TestKeys.Bob);
        ws.WriteBytes("in.bin", [1]);

        var result = ws.Run("encrypt", "-i", ws.Path("in.bin"), "-r", ws.Path("bob.pub"));

        Assert.Equal(Exit.Usage, result.ExitCode);
        Assert.Contains("--out", result.Stderr);
    }

    [Fact]
    public void InfoWithoutInput_IsAUsageError()
    {
        using var ws = new Workspace();

        var result = ws.Run("info");

        Assert.Equal(Exit.Usage, result.ExitCode);
        Assert.Contains("--in", result.Stderr);
    }

    [Fact]
    public void KeygenWithoutOutput_CreatesTheDefaultIdentity()
    {
        using var ws = new Workspace();

        var result = ws.Run("keygen", "--plaintext-key");

        // `shroud keygen` with nothing else is the whole setup step on a new machine.
        Assert.Equal(Exit.Ok, result.ExitCode);
        Assert.True(File.Exists(Path.Combine(ws.Home, "identity.key")));
        Assert.True(File.Exists(Path.Combine(ws.Home, "identity.pub")));
        Assert.Contains("default identity", result.Stdout);
        Assert.Contains("Back up the secret key", result.Stdout);
    }

    [Fact]
    public void KeygenTwice_WillNotSilentlyReplaceTheDefaultIdentity()
    {
        using var ws = new Workspace();

        ws.Run("keygen", "--plaintext-key");
        var result = ws.Run("keygen", "--plaintext-key");

        Assert.Equal(Exit.Usage, result.ExitCode);
        Assert.Contains("--force", result.Stderr);
    }

    [Fact]
    public void FileThatIsNotAPublicKey_IsRejectedAsABadContainer()
    {
        using var ws = new Workspace();
        ws.WriteBytes("in.bin", [1]);
        ws.WriteText("not-a-key.pub", "hello, this is not a key\n");

        var result = ws.Run("encrypt", "-i", ws.Path("in.bin"), "-o", ws.Path("out.shroud"),
            "-r", ws.Path("not-a-key.pub"));

        Assert.Equal(Exit.BadContainer, result.ExitCode);
        Assert.Contains("shroud-recipient:v2:", result.Stderr);
        Assert.False(ws.Exists("out.shroud"));
    }

    [Fact]
    public void FileThatIsNotAContainer_IsRejected()
    {
        using var ws = new Workspace();
        ws.WriteIdentity("bob", TestKeys.Bob);
        ws.WriteText("junk.shroud", "this is not a container at all, not even close");

        var decrypt = ws.Run("decrypt", "-i", ws.Path("junk.shroud"), "-o", ws.Path("out.bin"), "-k", ws.Path("bob.key"));
        var info = ws.Run("info", "-i", ws.Path("junk.shroud"));

        Assert.Equal(Exit.BadContainer, decrypt.ExitCode);
        Assert.Equal(Exit.BadContainer, info.ExitCode);
        Assert.Contains("bad magic", decrypt.Stderr);
        Assert.False(ws.Exists("out.bin"));
        Assert.Empty(ws.LeftoverPartials());
    }
}
