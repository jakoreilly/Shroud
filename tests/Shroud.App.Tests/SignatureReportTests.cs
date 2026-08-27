using Shroud.App;
using Shroud.Core;

namespace Shroud.App.Tests;

public sealed class SignatureReportTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("shroud-app-tests-").FullName;

    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Fact]
    public void Unsigned_HasNoFingerprintOrContact()
    {
        var workspace = new ShroudWorkspace(_root);
        var result = new DecryptionResult(WasSigned: false, Sender: null, SenderWasExpected: false, IsArchive: false);

        var report = SignatureReport.For(result, workspace);

        Assert.Equal(SignatureStanding.Unsigned, report.Standing);
        Assert.Null(report.Contact);
        Assert.Null(report.Fingerprint);
    }

    [Fact]
    public void SignedByUnknownKey_WhenSignerIsNotAContact()
    {
        var workspace = new ShroudWorkspace(_root);
        var sender = ShroudSecretKey.Generate().GetPublicKey();
        var result = new DecryptionResult(WasSigned: true, Sender: sender, SenderWasExpected: false, IsArchive: false);

        var report = SignatureReport.For(result, workspace);

        Assert.Equal(SignatureStanding.SignedByUnknownKey, report.Standing);
        Assert.Null(report.Contact);
        Assert.Equal(sender.Fingerprint(), report.Fingerprint);
    }

    [Fact]
    public void VerifiedContact_WhenSignerIsAKnownContact()
    {
        var workspace = new ShroudWorkspace(_root);
        var sender = ShroudSecretKey.Generate().GetPublicKey();
        workspace.Contacts.Add("alice", sender, sender.Fingerprint(), force: false);

        var result = new DecryptionResult(WasSigned: true, Sender: sender, SenderWasExpected: false, IsArchive: false);
        var report = SignatureReport.For(result, workspace);

        Assert.Equal(SignatureStanding.VerifiedContact, report.Standing);
        Assert.Equal("alice", report.Contact?.Name);
    }

    [Fact]
    public void ExpectedSender_WhenTheCallerPinnedTheIdentity()
    {
        var workspace = new ShroudWorkspace(_root);
        var sender = ShroudSecretKey.Generate().GetPublicKey();

        var result = new DecryptionResult(WasSigned: true, Sender: sender, SenderWasExpected: true, IsArchive: false);
        var report = SignatureReport.For(result, workspace);

        Assert.Equal(SignatureStanding.ExpectedSender, report.Standing);
    }

    [Fact]
    public void AllFourStandingsAreCovered()
    {
        Assert.Equal(4, Enum.GetValues<SignatureStanding>().Length);
    }
}
