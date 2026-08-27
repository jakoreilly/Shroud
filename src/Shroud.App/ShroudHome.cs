namespace Shroud.App;

/// <summary>
/// Where shroud keeps your identity and your contacts: <c>~/.shroud</c>, or whatever <c>SHROUD_HOME</c>
/// points at. Everything here is ordinary files you can read, copy and back up.
/// </summary>
public static class ShroudHome
{
    public const string EnvVar = "SHROUD_HOME";

    public static string Root =>
        Environment.GetEnvironmentVariable(EnvVar) is { Length: > 0 } custom
            ? custom
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".shroud");

    public static string ContactsDirectory => Path.Combine(Root, "contacts");

    public static string IdentityKeyPath => Path.Combine(Root, "identity.key");

    public static string IdentityPublicPath => Path.Combine(Root, "identity.pub");

    public static bool HasIdentity => File.Exists(IdentityKeyPath);

    /// <summary>Creates the home directory if it is missing, readable only by the current user.</summary>
    public static void Ensure() => EnsureDirectory(Root);

    public static void EnsureContacts()
    {
        Ensure();
        EnsureDirectory(ContactsDirectory);
    }

    /// <summary>
    /// Creates a directory if it is missing, readable only by the current user. Not tied to
    /// <see cref="Root"/>: a <c>ShroudWorkspace</c> pointed at a scratch directory for tests, or a
    /// second identity, uses this too.
    /// </summary>
    public static void EnsureDirectory(string directory)
    {
        if (Directory.Exists(directory))
            return;

        Directory.CreateDirectory(directory);
        Restrict(directory);
    }

    private static void Restrict(string directory)
    {
        try
        {
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(
                    directory,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or PlatformNotSupportedException or IOException)
        {
            Console.Error.WriteLine($"shroud: warning: could not restrict permissions on {directory}: {ex.Message}");
        }
    }
}
