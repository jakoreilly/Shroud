using Shroud.App;

namespace Shroud.App.Tests;

/// <summary>
/// Pins the CLI and the UI to the same four signature outcomes. If a fifth <see
/// cref="SignatureStanding"/> is ever added without updating <see cref="BannerMapping"/>, this is
/// the test that catches it -- see the reasoning in BannerMapping's doc comment for why C# cannot
/// make that a compile error on its own.
/// </summary>
public sealed class FrontEndParityTests
{
    [Fact]
    public void SignatureStanding_HasExactlyFourValues()
    {
        Assert.Equal(4, Enum.GetValues<SignatureStanding>().Length);
    }

    [Theory]
    [InlineData(SignatureStanding.ExpectedSender, "good")]
    [InlineData(SignatureStanding.VerifiedContact, "good")]
    [InlineData(SignatureStanding.SignedByUnknownKey, "caution")]
    [InlineData(SignatureStanding.Unsigned, "caution")]
    public void EveryStanding_MapsToABannerVariant(SignatureStanding standing, string expectedVariant)
    {
        var (variant, lead) = BannerMapping.ForBanner(standing);

        Assert.Equal(expectedVariant, variant);
        Assert.False(string.IsNullOrWhiteSpace(lead));
    }

    [Fact]
    public void EveryDeclaredStanding_IsHandledByBannerMapping()
    {
        // Exercises ForBanner for every value the enum currently declares, so growing the enum
        // without touching BannerMapping fails here (an unhandled value throws) rather than
        // rendering silently as one of the existing four in the running app.
        foreach (var standing in Enum.GetValues<SignatureStanding>())
        {
            var exception = Record.Exception(() => BannerMapping.ForBanner(standing));
            Assert.Null(exception);
        }
    }
}
