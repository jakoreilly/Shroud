using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Shroud.Core;

/// <summary>
/// Hybrid key encapsulation: ML-KEM-768 for post-quantum confidentiality, X25519 so that a
/// break of ML-KEM alone does not expose the file. Both shared secrets feed one HKDF-SHA256
/// extraction, so an attacker must break BOTH primitives to recover the file key.
/// </summary>
internal static class HybridKem
{
    internal readonly record struct Encapsulation(byte[] KemCiphertext, byte[] EphemeralPublicKey, byte[] SharedSecret);

    public static Encapsulation Encapsulate(ShroudPublicKey recipient)
    {
        var random = new SecureRandom();

        var encapsulator = new MLKemEncapsulator(MLKemParameters.ml_kem_768);
        encapsulator.Init(new ParametersWithRandom(recipient.MlKem, random));

        var kemCiphertext = new byte[encapsulator.EncapsulationLength];
        var mlKemSecret = new byte[encapsulator.SecretLength];
        encapsulator.Encapsulate(kemCiphertext, mlKemSecret);

        // Fresh ephemeral X25519 key per file; its public half travels in the header.
        var ephemeral = new X25519PrivateKeyParameters(random);
        var x25519Secret = Agree(ephemeral, recipient.X25519);

        return new Encapsulation(
            kemCiphertext,
            ephemeral.GeneratePublicKey().GetEncoded(),
            Concat(mlKemSecret, x25519Secret));
    }

    public static byte[] Decapsulate(ShroudSecretKey secretKey, byte[] kemCiphertext, byte[] ephemeralPublicKey)
    {
        if (kemCiphertext.Length != ShroudFormat.MlKemCiphertextLength)
            throw new ShroudFormatException("ML-KEM ciphertext has the wrong length.");
        if (ephemeralPublicKey.Length != ShroudFormat.X25519KeyLength)
            throw new ShroudFormatException("Ephemeral X25519 key has the wrong length.");

        var decapsulator = new MLKemDecapsulator(MLKemParameters.ml_kem_768);
        decapsulator.Init(secretKey.MlKem);

        // ML-KEM uses implicit rejection: a wrong or corrupted ciphertext yields a
        // pseudorandom secret rather than an error. The AEAD tag on the first chunk is
        // what actually tells us the key was wrong.
        var mlKemSecret = new byte[decapsulator.SecretLength];
        decapsulator.Decapsulate(kemCiphertext, mlKemSecret);

        var x25519Secret = Agree(secretKey.X25519, new X25519PublicKeyParameters(ephemeralPublicKey));

        return Concat(mlKemSecret, x25519Secret);
    }

    private static byte[] Agree(X25519PrivateKeyParameters privateKey, X25519PublicKeyParameters publicKey)
    {
        var agreement = new X25519Agreement();
        agreement.Init(privateKey);
        var secret = new byte[agreement.AgreementSize];
        // BouncyCastle rejects all-zero (small-order) outputs by throwing here.
        agreement.CalculateAgreement(publicKey, secret, 0);
        return secret;
    }

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var result = new byte[a.Length + b.Length];
        a.CopyTo(result, 0);
        b.CopyTo(result, a.Length);
        CryptographicOperations.ZeroMemory(a);
        CryptographicOperations.ZeroMemory(b);
        return result;
    }
}
