using Shroud.Core;

// The CLI is driven in-process, and redirecting Console is global state. Run one test at a time.
[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace Shroud.Cli.Tests;

internal sealed record CliResult(int ExitCode, string Stdout, string Stderr)
{
    /// <summary>Everything the command printed, for assertions that do not care which stream.</summary>
    public string Output => Stdout + Stderr;
}

/// <summary>
/// Exit codes the CLI promises. Scripts depend on these, so they are named here rather than
/// spelled as bare numbers in each test.
/// </summary>
internal static class Exit
{
    public const int Ok = 0;
    public const int BadContainer = 2;
    public const int Signature = 3;
    public const int Usage = 64;
    public const int Io = 74;
}

/// <summary>
/// Two identities, generated once for the whole run. Key generation is not what these tests are
/// about, and `keygen` has its own tests.
/// </summary>
internal static class TestKeys
{
    private static readonly Lazy<ShroudSecretKey> LazyAlice = new(ShroudSecretKey.Generate);

    private static readonly Lazy<ShroudSecretKey> LazyBob = new(ShroudSecretKey.Generate);

    public static ShroudSecretKey Alice => LazyAlice.Value;

    public static ShroudSecretKey Bob => LazyBob.Value;
}

/// <summary>A throwaway directory plus an in-process runner for the shroud command.</summary>
internal sealed class Workspace : IDisposable
{
    public const string KeyPassphrase = "the key passphrase";

    public const string FilePassphrase = "correct horse battery staple";

    private readonly string _root;

    public Workspace()
    {
        _root = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(),
            "shroud-cli-tests",
            Guid.NewGuid().ToString("n"));

        Directory.CreateDirectory(_root);
    }

    public string Path(string name) => System.IO.Path.Combine(_root, name);

    public bool Exists(string name) => File.Exists(Path(name));

    public string Text(string name) => File.ReadAllText(Path(name));

    public byte[] Bytes(string name) => File.ReadAllBytes(Path(name));

    /// <summary>Staging files the CLI must never leave behind, whatever went wrong.</summary>
    public string[] LeftoverPartials() =>
        [.. Directory.GetFiles(_root, "*.shroud-partial"), .. Directory.GetFiles(_root, "*.shroud-archive")];

    /// <summary>The SHROUD_HOME this workspace hands to the command under test.</summary>
    public string Home => Path("home");

    public string[] Entries(string directory) =>
        Directory.Exists(Path(directory))
            ? [.. Directory.GetFiles(Path(directory), "*", SearchOption.AllDirectories)]
            : [];

    public string WriteBytes(string name, byte[] content)
    {
        File.WriteAllBytes(Path(name), content);
        return Path(name);
    }

    public string WriteText(string name, string content)
    {
        File.WriteAllText(Path(name), content);
        return Path(name);
    }

    /// <summary>Writes a key pair the way keygen would, minus the comment header.</summary>
    public void WriteIdentity(string name, ShroudSecretKey key)
    {
        WriteText(name + ".key", key.ToArmoredString() + "\n");
        WriteText(name + ".pub", key.GetPublicKey().ToArmoredString() + "\n");
    }

    public void Corrupt(string name, int offset)
    {
        var bytes = Bytes(name);
        bytes[offset] ^= 0x01;
        WriteBytes(name, bytes);
    }

    /// <summary>
    /// Runs the command with both passphrase environment variables set, so no test can reach a
    /// console prompt and block the run.
    /// </summary>
    public CliResult Run(params string[] args) => RunWith(FilePassphrase, KeyPassphrase, args);

    public CliResult RunWith(string? filePassphrase, string? keyPassphrase, params string[] args)
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var previousOut = Console.Out;
        var previousError = Console.Error;
        var previousFile = Environment.GetEnvironmentVariable("SHROUD_PASSPHRASE");
        var previousKey = Environment.GetEnvironmentVariable("SHROUD_KEY_PASSPHRASE");
        var previousHome = Environment.GetEnvironmentVariable("SHROUD_HOME");

        try
        {
            Console.SetOut(stdout);
            Console.SetError(stderr);
            Environment.SetEnvironmentVariable("SHROUD_PASSPHRASE", filePassphrase);
            Environment.SetEnvironmentVariable("SHROUD_KEY_PASSPHRASE", keyPassphrase);

            // Identity and contacts live inside the throwaway workspace, never in the real
            // ~/.shroud of whoever is running the tests.
            Environment.SetEnvironmentVariable("SHROUD_HOME", Path("home"));

            // Anything Program.Main does not catch escapes here and fails the test, which is the
            // point: an unhandled exception is a bug even when the exit code would look right.
            return new CliResult(Program.Main(args), stdout.ToString(), stderr.ToString());
        }
        finally
        {
            Console.SetOut(previousOut);
            Console.SetError(previousError);
            Environment.SetEnvironmentVariable("SHROUD_PASSPHRASE", previousFile);
            Environment.SetEnvironmentVariable("SHROUD_KEY_PASSPHRASE", previousKey);
            Environment.SetEnvironmentVariable("SHROUD_HOME", previousHome);
        }
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // A leaked temp directory is not worth failing a test over.
        }
    }
}
