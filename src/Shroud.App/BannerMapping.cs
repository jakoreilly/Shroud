namespace Shroud.App;

/// <summary>
/// Maps a <see cref="SignatureStanding"/> to a banner variant and leading word -- the UI's half of
/// the same four-way decision the CLI's <c>ReportSignature</c> switches on. Kept here rather than
/// in Shroud.Ui, even though only the UI renders it, so <c>FrontEndParityTests</c> can pin both front
/// ends to the same four cases without a headless UI harness.
///
/// Every named case is listed explicitly rather than folded into a catch-all, so a fifth standing
/// added to <see cref="SignatureStanding"/> without a decision here throws immediately instead of
/// silently rendering as one of the existing four. C#'s enum exhaustiveness checking cannot make
/// that a compile error on its own (a switch expression over an enum always requires a catch-all,
/// since the underlying value is not restricted to named members) -- FrontEndParityTests closes
/// that gap by asserting <c>SignatureStanding</c> has exactly four values and exercising all of
/// them through this method.
/// </summary>
public static class BannerMapping
{
    public static (string Variant, string Lead) ForBanner(SignatureStanding standing) => standing switch
    {
        SignatureStanding.ExpectedSender => ("good", "Verified"),
        SignatureStanding.VerifiedContact => ("good", "Verified"),
        SignatureStanding.SignedByUnknownKey => ("caution", "Not verified"),
        SignatureStanding.Unsigned => ("caution", "Unsigned"),
        _ => throw new ArgumentOutOfRangeException(nameof(standing), standing, "Unhandled signature standing."),
    };
}
