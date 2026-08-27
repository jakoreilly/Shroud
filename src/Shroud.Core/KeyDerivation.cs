using System.Security.Cryptography;

namespace Shroud.Core;

/// <summary>
/// Derives the 256-bit file key. Both modes bind the header hash in as the HKDF salt, so the
/// chunk size, suite, flags, KEM ciphertext and Argon2 costs are all authenticated by the key
/// itself: editing any of them yields a different key and the first chunk fails to authenticate.
/// </summary>
internal static class KeyDerivation
{
    /// <summary>
    /// Combines the ML-KEM and X25519 secrets. The recipient's public key goes into the HKDF
    /// info string, which binds the derived key to the intended recipient and stops an attacker
    /// re-using a captured encapsulation under a different identity.
    /// </summary>
    public static byte[] ForRecipient(byte[] hybridSecret, ShroudPublicKey recipient, byte[] headerHash)
    {
        var context = ShroudFormat.HybridKemInfo;
        var info = new byte[context.Length + ShroudFormat.PublicKeyBlobLength];
        context.CopyTo(info);
        recipient.ToBlob().CopyTo(info, context.Length);

        try
        {
            return HKDF.DeriveKey(
                HashAlgorithmName.SHA256,
                ikm: hybridSecret,
                outputLength: ShroudFormat.FileKeyLength,
                salt: headerHash,
                info: info);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hybridSecret);
        }
    }

    public static byte[] ForPassphrase(string passphrase, FileHeader header)
    {
        var salt = header.Salt ?? throw new InvalidOperationException("Passphrase header has no salt.");
        var settings = header.Argon2 ?? throw new InvalidOperationException("Passphrase header has no Argon2 settings.");

        var master = Argon2.Derive(passphrase, salt, settings, ShroudFormat.FileKeyLength);

        try
        {
            return HKDF.DeriveKey(
                HashAlgorithmName.SHA256,
                ikm: master,
                outputLength: ShroudFormat.FileKeyLength,
                salt: header.ComputeHash(),
                info: ShroudFormat.PassphraseInfo.ToArray());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(master);
        }
    }
}
