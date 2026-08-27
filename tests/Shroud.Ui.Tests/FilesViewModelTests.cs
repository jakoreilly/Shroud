using Shroud.App;
using Shroud.Ui.ViewModels;

namespace Shroud.Ui.Tests;

public sealed class FilesViewModelTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("shroud-ui-tests-").FullName;

    public void Dispose() => Directory.Delete(_root, recursive: true);

    private string Path(string name) => System.IO.Path.Combine(_root, name);

    private (ShroudWorkspace Workspace, FilesViewModel ViewModel) NewFixture()
    {
        var workspace = new ShroudWorkspace(Path("home"));
        var vm = new FilesViewModel(workspace, new ShroudEngine(workspace));
        return (workspace, vm);
    }

    [Fact]
    public void SetInput_OnAnOrdinaryFile_SelectsEncryptModeWithADerivedOutputPath()
    {
        var (_, vm) = NewFixture();
        var plain = Path("report.txt");
        File.WriteAllText(plain, "hello");

        vm.SetInput(plain);

        Assert.True(vm.IsEncryptMode);
        Assert.False(vm.IsDecryptMode);
        Assert.Equal(plain + ".shroud", vm.OutputPath);
        Assert.False(vm.CanRun); // no recipient and no passphrase chosen yet
    }

    [Fact]
    public void SetInput_OnADirectory_SelectsEncryptMode()
    {
        var (_, vm) = NewFixture();
        var dir = Path("records");
        Directory.CreateDirectory(dir);

        vm.SetInput(dir);

        Assert.True(vm.IsEncryptMode);
        Assert.Equal(dir + ".shroud", vm.OutputPath);
    }

    [Fact]
    public void ClearInput_ReturnsToTheIdleState()
    {
        var (_, vm) = NewFixture();
        var plain = Path("report.txt");
        File.WriteAllText(plain, "hello");
        vm.SetInput(plain);

        vm.ClearInput();

        Assert.False(vm.HasInput);
        Assert.Null(vm.InputPath);
        Assert.Null(vm.OutputPath);
    }

    [Fact]
    public async Task EncryptThenDecrypt_ByPassphrase_RoundTripsAndReportsUnsigned()
    {
        var (_, vm) = NewFixture();
        var plain = Path("report.txt");
        File.WriteAllText(plain, "the report");

        vm.SetInput(plain);
        vm.UsePassphraseForEncrypt = true;
        vm.EncryptPassphrase = "correct horse battery staple";
        vm.ConfirmEncryptPassphrase = "correct horse battery staple";
        Assert.True(vm.CanRun);

        await vm.RunAsync();

        Assert.True(vm.ResultIsGood);
        Assert.True(File.Exists(vm.OutputPath));

        var container = vm.OutputPath!;
        File.Delete(plain); // else the derived decrypt output collides with the original plaintext
        vm.SetInput(container);

        Assert.True(vm.IsDecryptMode);
        Assert.True(vm.UsePassphraseForDecrypt); // Inspect reported passphrase mode
        Assert.False(vm.IsSignedContainer);

        vm.DecryptPassphrase = "correct horse battery staple";
        Assert.True(vm.CanRun);

        await vm.RunAsync();

        Assert.True(vm.ResultIsCaution);
        Assert.Equal("Unsigned", vm.Result?.Lead);
        Assert.Equal("the report", File.ReadAllText(vm.OutputPath!));
    }

    [Fact]
    public async Task EncryptThenDecrypt_ToARecipient_SignedAndPinned_ReportsExpectedSender()
    {
        var (workspace, vm) = NewFixture();
        IdentityService.CreateDefault(workspace, passphrase: null, force: false);

        var plain = Path("report.txt");
        File.WriteAllText(plain, "the report");

        vm.SetInput(plain);
        vm.RecipientKeyFilePath = workspace.IdentityPublicPath; // encrypt to "yourself" for the test
        vm.SignAsMe = true;
        Assert.True(vm.CanRun);

        await vm.RunAsync();

        Assert.True(vm.ResultIsGood);

        // Not yet a known contact of its own signer: reported as signed-but-unrecognised. Each
        // decrypt below gets its own output path -- the auto-derived default is for the single
        // common case, not for re-decrypting the same container repeatedly within one test.
        var container = vm.OutputPath!;
        vm.SetInput(container);
        vm.OutputPath = Path("first.out");
        Assert.True(vm.IsSignedContainer);
        Assert.True(vm.CanRun); // identity key is unprotected, no passphrase needed

        await vm.RunAsync();
        Assert.True(vm.ResultIsCaution);
        Assert.Equal("Not verified", vm.Result?.Lead);

        // Pin the identity's own key as a contact and expect it explicitly.
        var publicKey = Shroud.Core.ShroudPublicKey.Parse(File.ReadAllText(workspace.IdentityPublicPath));
        workspace.Contacts.Add("me", publicKey, publicKey.Fingerprint(), force: false);

        vm.SetInput(container);
        vm.OutputPath = Path("second.out");
        vm.SelectedExpectedSender = vm.Contacts.Single();

        await vm.RunAsync();

        Assert.True(vm.ResultIsGood);
        Assert.Equal("Verified", vm.Result?.Lead);
    }

    [Fact]
    public async Task Decrypt_RefusesAnExistingOutput_AndReplaceRetriesWithForce()
    {
        var (_, vm) = NewFixture();
        var plain = Path("report.txt");
        File.WriteAllText(plain, "the report");

        vm.SetInput(plain);
        vm.UsePassphraseForEncrypt = true;
        vm.EncryptPassphrase = "x";
        vm.ConfirmEncryptPassphrase = "x";
        await vm.RunAsync();

        var container = vm.OutputPath!;
        vm.SetInput(container);
        vm.UsePassphraseForDecrypt = true;
        vm.DecryptPassphrase = "x";

        // Something already sitting at the derived output path.
        File.WriteAllText(vm.OutputPath!, "already here");

        await vm.RunAsync();

        Assert.True(vm.AwaitingForceConfirmation);
        Assert.Equal("already here", File.ReadAllText(vm.OutputPath!));

        await vm.RetryWithForceAsync();

        Assert.Equal("the report", File.ReadAllText(vm.OutputPath!));
    }
}
