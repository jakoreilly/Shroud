namespace Shroud.App;

/// <summary>
/// One user's shroud state: where their identity lives and which contacts they have checked.
///
/// Instance rather than static so a test -- or a second window -- can point at a scratch directory
/// without setting a process-wide environment variable. <see cref="FromEnvironment"/> preserves
/// the existing SHROUD_HOME behaviour exactly for the CLI.
/// </summary>
public sealed class ShroudWorkspace
{
    public ShroudWorkspace(string root)
    {
        ArgumentException.ThrowIfNullOrEmpty(root);
        Root = root;
        Contacts = new ContactStore(Path.Combine(root, "contacts"));
    }

    public static ShroudWorkspace FromEnvironment() => new(ShroudHome.Root);

    public string Root { get; }

    public ContactStore Contacts { get; }

    public string IdentityKeyPath => Path.Combine(Root, "identity.key");

    public string IdentityPublicPath => Path.Combine(Root, "identity.pub");

    public bool HasIdentity => File.Exists(IdentityKeyPath);

    /// <summary>Creates the workspace root if it is missing, readable only by the current user.</summary>
    public void EnsureExists() => ShroudHome.EnsureDirectory(Root);
}
