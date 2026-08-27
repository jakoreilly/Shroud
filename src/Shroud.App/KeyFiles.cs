using Shroud.Core;

namespace Shroud.App;

/// <summary>
/// Writes shroud's armoured key files -- the comment header, the restricted permissions -- so the CLI
/// and the UI's identity-creation flow produce byte-identical files instead of two implementations
/// of the same security-sensitive formatting.
/// </summary>
public static class KeyFiles
{
    public static void WriteSecretKey(string path, ShroudSecretKey key, string? passphrase, string fingerprint)
    {
        var armoured = passphrase is null ? key.ToArmoredString() : key.ToArmoredString(passphrase);
        var protection = passphrase is null ? "UNENCRYPTED" : "Argon2id + AES-256-GCM";

        File.WriteAllText(
            path,
            $"# Shroud secret key, fingerprint {fingerprint}, protection: {protection}.\n"
                + "# Keep this file private. It is both your decryption key and your signing key.\n"
                + armoured
                + "\n");
        Restrict(path);
    }

    public static void WritePublicKey(string path, ShroudPublicKey key, string fingerprint)
    {
        File.WriteAllText(
            path,
            $"# Shroud public key, fingerprint {fingerprint}. Safe to share.\n"
                + key.ToArmoredString()
                + "\n");
    }

    /// <summary>Removes inherited access so only the current user can read a freshly written secret key.</summary>
    public static void Restrict(string path)
    {
        try
        {
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                return;
            }

            var info = new FileInfo(path);
            var security = info.GetAccessControl();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            var user = System.Security.Principal.WindowsIdentity.GetCurrent().User;
            if (user is not null)
            {
                security.AddAccessRule(
                    new System.Security.AccessControl.FileSystemAccessRule(
                        user,
                        System.Security.AccessControl.FileSystemRights.FullControl,
                        System.Security.AccessControl.AccessControlType.Allow));
            }

            info.SetAccessControl(security);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or PlatformNotSupportedException)
        {
            Console.Error.WriteLine($"shroud: warning: could not restrict permissions on {path}: {ex.Message}");
        }
    }
}
