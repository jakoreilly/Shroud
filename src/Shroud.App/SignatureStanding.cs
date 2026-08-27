using Shroud.Core;

namespace Shroud.App;

/// <summary>
/// What a decryption established about origin. These four cases are exhaustive and mirror, one
/// for one, the four branches the CLI has always printed.
///
/// This lives here, in one function, so a second front end cannot invent a fifth case or quietly
/// merge two of them. Adding a case is a deliberate edit in one place, reviewed once.
/// </summary>
public enum SignatureStanding
{
    /// <summary>No signature at all. Nothing establishes who produced the container.</summary>
    Unsigned,

    /// <summary>Valid signature by a key that is not one of your contacts. Not evidence of origin.</summary>
    SignedByUnknownKey,

    /// <summary>Valid signature by a key whose fingerprint you confirmed when you added the contact.</summary>
    VerifiedContact,

    /// <summary>Valid signature, and it matched the identity the caller named in advance.</summary>
    ExpectedSender,
}

/// <param name="Standing">Which of the four cases applies.</param>
/// <param name="Contact">The matching contact, when the signer is one. Never a bare name -- render
/// with <see cref="App.Contact.ToString"/> so the fingerprint travels with it.</param>
/// <param name="Fingerprint">The signer's fingerprint, or null when unsigned.</param>
public sealed record SignatureReport(SignatureStanding Standing, Contact? Contact, string? Fingerprint)
{
    /// <summary>
    /// Classifies a decryption result against the contact store. The only function permitted to
    /// decide what a signature means.
    /// </summary>
    public static SignatureReport For(DecryptionResult result, ShroudWorkspace workspace)
    {
        if (!result.WasSigned)
            return new SignatureReport(SignatureStanding.Unsigned, null, null);

        var contact = result.Sender is null ? null : workspace.Contacts.ByKey(result.Sender);

        var standing = result.SenderWasExpected
            ? SignatureStanding.ExpectedSender
            : contact is not null
                ? SignatureStanding.VerifiedContact
                : SignatureStanding.SignedByUnknownKey;

        return new SignatureReport(standing, contact, result.SenderFingerprint);
    }
}
