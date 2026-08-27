using Shroud.Core;

namespace Shroud.App;

/// <summary>Result of writing a fresh identity to disk.</summary>
public sealed record IdentityCreationResult(string SecretPath, string PublicPath, string Fingerprint, bool Protected);

/// <summary>
/// Creates a fresh identity: an ML-KEM-768 + X25519 + ML-DSA-65 key pair, written as shroud's armoured
/// key files. The CLI's <c>keygen</c> and the UI's identity screen both call this, so they cannot
/// produce different files for what is meant to be the same operation.
/// </summary>
public static class IdentityService
{
    public static IdentityCreationResult CreateAt(string secretPath, string publicPath, string? passphrase, bool force)
    {
        foreach (var path in new[] { secretPath, publicPath })
        {
            if (File.Exists(path) && !force)
                throw new ShroudWorkspaceException($"{path} already exists. Pass --force to overwrite.");
        }

        var secretKey = ShroudSecretKey.Generate();
        var publicKey = secretKey.GetPublicKey();
        var fingerprint = publicKey.Fingerprint();

        KeyFiles.WriteSecretKey(secretPath, secretKey, passphrase, fingerprint);
        KeyFiles.WritePublicKey(publicPath, publicKey, fingerprint);

        return new IdentityCreationResult(secretPath, publicPath, fingerprint, Protected: passphrase is not null);
    }

    /// <summary>Creates the workspace's default identity, ensuring the workspace root exists first.</summary>
    public static IdentityCreationResult CreateDefault(ShroudWorkspace workspace, string? passphrase, bool force)
    {
        workspace.EnsureExists();
        return CreateAt(workspace.IdentityKeyPath, workspace.IdentityPublicPath, passphrase, force);
    }
}
