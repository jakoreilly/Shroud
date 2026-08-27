using Shroud.Core;

namespace Shroud.App;

public sealed record Contact(string Name, ShroudPublicKey Key)
{
    public string Fingerprint => Key.Fingerprint();

    /// <summary>How a contact must always be shown: a name is only meaningful beside its key.</summary>
    public override string ToString() => $"{Name} ({Fingerprint})";
}

/// <summary>
/// Public keys you have checked, stored as ordinary <c>.pub</c> files under a contacts directory.
///
/// A contact is a name bound to a key, and the binding is only as good as the check you did when
/// you added it -- which is why <see cref="Add"/> demands the fingerprint you were told out of
/// band and refuses if it does not match. Anyone can generate a key and call themselves anything;
/// this store exists so you only have to do that comparison once instead of on every file.
///
/// The store itself is not tamper-proof. Someone who can write to the directory can swap a
/// contact's key, so every command that resolves a name prints the fingerprint alongside it.
///
/// Instance rather than static so a test -- or a second window -- can point at a scratch directory
/// without touching a process-wide environment variable.
/// </summary>
public sealed class ContactStore(string directory)
{
    private const int MaxNameLength = 64;

    public IReadOnlyList<Contact> All()
    {
        if (!Directory.Exists(directory))
            return [];

        var contacts = new List<Contact>();

        foreach (var path in Directory.EnumerateFiles(directory, "*.pub"))
        {
            var name = Path.GetFileNameWithoutExtension(path);

            try
            {
                contacts.Add(new Contact(name, ShroudPublicKey.Parse(File.ReadAllText(path))));
            }
            catch (ShroudFormatException ex)
            {
                Console.Error.WriteLine($"shroud: warning: ignoring unreadable contact {name}: {ex.Message}");
            }
        }

        contacts.Sort((a, b) => string.CompareOrdinal(a.Name, b.Name));
        return contacts;
    }

    public Contact? ByName(string name)
    {
        if (!IsValidName(name))
            return null;

        var path = PathFor(name);
        return File.Exists(path) ? new Contact(name, ShroudPublicKey.Parse(File.ReadAllText(path))) : null;
    }

    /// <summary>
    /// Finds the contact holding this exact key. The whole 3168-byte blob is compared, not the
    /// fingerprint: a fingerprint is a truncated hash, and identifying a sender is not the place
    /// to accept a 64-bit match.
    /// </summary>
    public Contact? ByKey(ShroudPublicKey key)
    {
        var blob = key.ToBlob();

        foreach (var contact in All())
        {
            if (contact.Key.ToBlob().AsSpan().SequenceEqual(blob))
                return contact;
        }

        return null;
    }

    public void Add(string name, ShroudPublicKey key, string expectedFingerprint, bool force)
    {
        ValidateName(name);

        var actual = key.Fingerprint();
        var expected = expectedFingerprint.Trim().Replace(" ", string.Empty).ToLowerInvariant();

        if (!string.Equals(actual, expected, StringComparison.Ordinal))
        {
            throw new ShroudWorkspaceException(
                $"Fingerprint mismatch: this key is {actual}, you said {expected}. "
                    + "Do not add it. Get the fingerprint from the other person again, over a channel "
                    + "the key itself did not travel on.");
        }

        var path = PathFor(name);

        if (File.Exists(path) && !force)
            throw new ShroudWorkspaceException($"Contact '{name}' already exists. Pass --force to replace it.");

        ShroudHome.EnsureDirectory(directory);

        File.WriteAllText(
            path,
            $"# Shroud contact {name}, fingerprint {actual}.\n"
                + $"# Fingerprint confirmed on {DateTime.Now:yyyy-MM-dd}.\n"
                + key.ToArmoredString()
                + "\n");
    }

    public bool Remove(string name)
    {
        ValidateName(name);

        var path = PathFor(name);

        if (!File.Exists(path))
            return false;

        File.Delete(path);
        return true;
    }

    /// <summary>
    /// True if the text could be a contact name rather than a path. Used to decide whether a
    /// <c>--recipient</c> value that is not an existing file is worth looking up. Static and pure,
    /// so a UI can validate a name field live without needing a store instance.
    /// </summary>
    public static bool IsValidName(string name) =>
        name.Length is > 0 and <= MaxNameLength
        && name is not ("." or "..")
        && name.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-');

    private static void ValidateName(string name)
    {
        if (!IsValidName(name))
        {
            throw new ShroudWorkspaceException(
                $"'{name}' is not a usable contact name. Use letters, digits, dot, dash and "
                    + $"underscore, up to {MaxNameLength} characters.");
        }
    }

    private string PathFor(string name) => Path.Combine(directory, name + ".pub");
}
