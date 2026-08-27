using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Shroud.Core;

internal static class Argon2
{
    public static byte[] Derive(string passphrase, byte[] salt, Argon2Settings settings, int outputLength)
    {
        settings.Validate();

        var passphraseBytes = System.Text.Encoding.UTF8.GetBytes(passphrase);
        var output = new byte[outputLength];

        try
        {
            var parameters = new Argon2Parameters.Builder(Argon2Parameters.Argon2id)
                .WithVersion(Argon2Parameters.Version13)
                .WithSalt(salt)
                .WithIterations(settings.Iterations)
                .WithMemoryAsKB(settings.MemoryKib)
                .WithParallelism(settings.Lanes)
                .Build();

            var generator = new Argon2BytesGenerator();
            generator.Init(parameters);
            generator.GenerateBytes(passphraseBytes, output);

            return output;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passphraseBytes);
        }
    }
}
