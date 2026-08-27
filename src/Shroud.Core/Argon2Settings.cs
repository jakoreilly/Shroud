namespace Shroud.Core;

/// <summary>Argon2id cost parameters, recorded alongside the ciphertext so they can be reproduced.</summary>
public sealed record Argon2Settings(int Iterations, int MemoryKib, int Lanes)
{
    /// <summary>64 MiB, 3 passes, 4 lanes. Above the RFC 9106 second recommended option.</summary>
    public static Argon2Settings Default { get; } = new(Iterations: 3, MemoryKib: 65536, Lanes: 4);

    /// <summary>
    /// 128 MiB, 4 passes for key files. Deliberately costlier than <see cref="Default"/>: a key
    /// file is unwrapped once per session, and it guards a long-lived secret rather than one file.
    /// </summary>
    public static Argon2Settings KeyFileDefault { get; } = new(Iterations: 4, MemoryKib: 131072, Lanes: 4);

    /// <summary>Rejects values that are unusable or that a hostile file could use to exhaust memory.</summary>
    public void Validate()
    {
        if (Iterations is < 1 or > 32)
            throw new ShroudFormatException($"Argon2id iterations out of range: {Iterations}");

        // Capped at 1 GiB: these costs come from an untrusted header, so a hostile file must
        // not be able to talk us into an unbounded allocation.
        if (MemoryKib < 8 || MemoryKib > 1024 * 1024)
            throw new ShroudFormatException($"Argon2id memory out of range: {MemoryKib} KiB");
        if (Lanes is < 1 or > 64)
            throw new ShroudFormatException($"Argon2id lanes out of range: {Lanes}");
        if (MemoryKib < 8 * Lanes)
            throw new ShroudFormatException($"Argon2id memory {MemoryKib} KiB too small for {Lanes} lanes");
    }
}
