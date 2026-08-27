using System.Collections.ObjectModel;
using System.Windows.Input;
using Shroud.App;
using Shroud.Core;

namespace Shroud.Ui.ViewModels;

public enum FilesMode
{
    None,
    Encrypt,
    Decrypt,
}

/// <summary>Outcome banner: <see cref="Variant"/> is a CSS class (good/caution/bad/neutral),
/// <see cref="Lead"/> is the word that must carry the meaning even in greyscale.</summary>
public sealed record ResultBanner(string Variant, string Lead, string Body);

/// <summary>
/// Drives the Files screen: inspect a dropped path, show the matching panel, run the operation off
/// the UI thread with progress and cancellation, and report the outcome through the banner table.
/// Everything here goes through <see cref="IShroudEngine"/> -- the same staging/verify/extract
/// ordering the CLI uses -- so this view model only ever assembles requests, never re-implements
/// that ordering.
/// </summary>
public sealed class FilesViewModel : ViewModelBase
{
    private readonly ShroudWorkspace _workspace;
    private readonly IShroudEngine _engine;

    private CancellationTokenSource? _cts;
    private bool _forceNext;

    private FilesMode _mode;
    private string? _inputPath;
    private bool _isDirectory;
    private ContainerSummary? _summary;
    private string? _outputPath;

    private Contact? _selectedRecipient;
    private string? _recipientKeyFilePath;
    private bool _usePassphraseForEncrypt;
    private string _encryptPassphrase = string.Empty;
    private string _confirmEncryptPassphrase = string.Empty;
    private bool _signAsMe;

    private bool _usePassphraseForDecrypt;
    private string _decryptPassphrase = string.Empty;
    private Contact? _selectedExpectedSender;
    private bool _extractArchive;

    private string _identityPassphrase = string.Empty;

    private bool _isBusy;
    private double _progress;
    private string _busyLabel = string.Empty;
    private ResultBanner? _result;
    private bool _awaitingForceConfirmation;

    public FilesViewModel(ShroudWorkspace workspace, IShroudEngine engine)
    {
        _workspace = workspace;
        _engine = engine;
        _signAsMe = workspace.HasIdentity;

        RunCommand = new AsyncRelayCommand(RunAsync, () => CanRun && !IsBusy);
        CancelCommand = new RelayCommand(() => _cts?.Cancel(), () => IsBusy);
        ReplaceCommand = new RelayCommand(() => _ = RetryWithForceAsync(), () => AwaitingForceConfirmation);

        RefreshContacts();
    }

    // ---- picker seams the view wires to platform dialogs; the view model has no Avalonia types --

    public Func<Task<string?>>? PickInputFile { get; set; }
    public Func<Task<string?>>? PickInputFolder { get; set; }
    public Func<string, Task<string?>>? PickOutputFile { get; set; }
    public Func<Task<string?>>? PickOutputFolder { get; set; }
    public Func<Task<string?>>? PickRecipientKeyFile { get; set; }

    // ---- state -------------------------------------------------------------------------------

    public ObservableCollection<Contact> Contacts { get; } = [];

    public FilesMode Mode
    {
        get => _mode;
        private set
        {
            if (SetField(ref _mode, value))
            {
                RaisePropertyChanged(nameof(IsEncryptMode));
                RaisePropertyChanged(nameof(IsDecryptMode));
            }
        }
    }

    public bool IsEncryptMode => Mode == FilesMode.Encrypt;

    public bool IsDecryptMode => Mode == FilesMode.Decrypt;

    public bool HasInput => InputPath is not null;

    public string? InputPath { get => _inputPath; private set => SetField(ref _inputPath, value); }

    public ContainerSummary? Summary
    {
        get => _summary;
        private set
        {
            if (SetField(ref _summary, value))
            {
                RaisePropertyChanged(nameof(IsSignedContainer));
                RaisePropertyChanged(nameof(IsArchiveContainer));
            }
        }
    }

    public bool IsSignedContainer => Summary?.IsSigned == true;

    public bool IsArchiveContainer => Summary?.IsArchive == true;

    public bool HasIdentity => _workspace.HasIdentity;

    public string? OutputPath
    {
        get => _outputPath;
        set
        {
            if (SetField(ref _outputPath, value))
                ((AsyncRelayCommand)RunCommand).RaiseCanExecuteChanged();
        }
    }

    public Contact? SelectedRecipient
    {
        get => _selectedRecipient;
        set
        {
            if (SetField(ref _selectedRecipient, value))
                ((AsyncRelayCommand)RunCommand).RaiseCanExecuteChanged();
        }
    }

    public string? RecipientKeyFilePath
    {
        get => _recipientKeyFilePath;
        internal set
        {
            if (SetField(ref _recipientKeyFilePath, value))
                ((AsyncRelayCommand)RunCommand).RaiseCanExecuteChanged();
        }
    }

    public bool UsePassphraseForEncrypt
    {
        get => _usePassphraseForEncrypt;
        set
        {
            if (SetField(ref _usePassphraseForEncrypt, value))
                ((AsyncRelayCommand)RunCommand).RaiseCanExecuteChanged();
        }
    }

    public string EncryptPassphrase
    {
        get => _encryptPassphrase;
        set
        {
            if (SetField(ref _encryptPassphrase, value))
                ((AsyncRelayCommand)RunCommand).RaiseCanExecuteChanged();
        }
    }

    public string ConfirmEncryptPassphrase
    {
        get => _confirmEncryptPassphrase;
        set
        {
            if (SetField(ref _confirmEncryptPassphrase, value))
                ((AsyncRelayCommand)RunCommand).RaiseCanExecuteChanged();
        }
    }

    public bool SignAsMe { get => _signAsMe; set => SetField(ref _signAsMe, value); }

    public bool UsePassphraseForDecrypt
    {
        get => _usePassphraseForDecrypt;
        set
        {
            if (SetField(ref _usePassphraseForDecrypt, value))
                ((AsyncRelayCommand)RunCommand).RaiseCanExecuteChanged();
        }
    }

    public string DecryptPassphrase
    {
        get => _decryptPassphrase;
        set
        {
            if (SetField(ref _decryptPassphrase, value))
                ((AsyncRelayCommand)RunCommand).RaiseCanExecuteChanged();
        }
    }

    /// <summary>Null means "Anyone (just tell me who)" -- the caller has not pinned an expected
    /// identity, so a valid-but-unrecognised signer is reported, not silently accepted.</summary>
    public Contact? SelectedExpectedSender { get => _selectedExpectedSender; set => SetField(ref _selectedExpectedSender, value); }

    public bool ExtractArchive { get => _extractArchive; set => SetField(ref _extractArchive, value); }

    /// <summary>Only unlocking your own local key file, never a trust decision, so pre-filling this
    /// (unlike a contact's fingerprint) raises no concern.</summary>
    public string IdentityPassphrase { get => _identityPassphrase; set => SetField(ref _identityPassphrase, value); }

    public bool IsBusy
    {
        get => _isBusy;
        private set
        {
            if (SetField(ref _isBusy, value))
            {
                ((AsyncRelayCommand)RunCommand).RaiseCanExecuteChanged();
                ((RelayCommand)CancelCommand).RaiseCanExecuteChanged();
            }
        }
    }

    public double Progress { get => _progress; private set => SetField(ref _progress, value); }

    public string BusyLabel { get => _busyLabel; private set => SetField(ref _busyLabel, value); }

    public ResultBanner? Result
    {
        get => _result;
        private set
        {
            if (SetField(ref _result, value))
            {
                RaisePropertyChanged(nameof(HasResult));
                RaisePropertyChanged(nameof(ResultIsGood));
                RaisePropertyChanged(nameof(ResultIsCaution));
                RaisePropertyChanged(nameof(ResultIsBad));
                RaisePropertyChanged(nameof(ResultIsNeutral));
            }
        }
    }

    public bool HasResult => Result is not null;
    public bool ResultIsGood => Result?.Variant == "good";
    public bool ResultIsCaution => Result?.Variant == "caution";
    public bool ResultIsBad => Result?.Variant == "bad";
    public bool ResultIsNeutral => Result?.Variant == "neutral";

    public bool AwaitingForceConfirmation
    {
        get => _awaitingForceConfirmation;
        private set
        {
            if (SetField(ref _awaitingForceConfirmation, value))
                ((RelayCommand)ReplaceCommand).RaiseCanExecuteChanged();
        }
    }

    public bool CanRun =>
        InputPath is not null
        && !string.IsNullOrWhiteSpace(OutputPath)
        && Mode switch
        {
            FilesMode.Encrypt => UsePassphraseForEncrypt
                ? EncryptPassphrase.Length > 0 && EncryptPassphrase == ConfirmEncryptPassphrase
                : SelectedRecipient is not null || RecipientKeyFilePath is not null,
            FilesMode.Decrypt => UsePassphraseForDecrypt ? DecryptPassphrase.Length > 0 : HasIdentity,
            _ => false,
        };

    public ICommand RunCommand { get; }
    public ICommand CancelCommand { get; }
    public ICommand ReplaceCommand { get; }

    // ---- input selection -----------------------------------------------------------------------

    public async Task ChooseInputFileAsync()
    {
        if (PickInputFile is { } pick && await pick() is { } path)
            SetInput(path);
    }

    public async Task ChooseInputFolderAsync()
    {
        if (PickInputFolder is { } pick && await pick() is { } path)
            SetInput(path);
    }

    public async Task ChooseRecipientKeyFileAsync()
    {
        if (PickRecipientKeyFile is { } pick && await pick() is { } path)
            RecipientKeyFilePath = path;
    }

    public async Task ChooseOutputAsync()
    {
        string? chosen = Mode == FilesMode.Decrypt && ExtractArchive && Summary is { IsArchive: true }
            ? PickOutputFolder is null ? null : await PickOutputFolder()
            : PickOutputFile is null ? null : await PickOutputFile(SuggestedOutputName());

        if (chosen is not null)
            OutputPath = chosen;
    }

    public void SetInput(string path)
    {
        Result = null;
        AwaitingForceConfirmation = false;
        _forceNext = false;
        RecipientKeyFilePath = null;
        SelectedRecipient = null;
        SelectedExpectedSender = null;

        InputPath = path;
        RaisePropertyChanged(nameof(HasInput));
        _isDirectory = Directory.Exists(path);

        if (_isDirectory)
        {
            Mode = FilesMode.Encrypt;
            Summary = null;
            OutputPath = path + ".shroud";
        }
        else
        {
            var summary = _engine.Inspect(path);
            Summary = summary;

            if (summary.IsContainer)
            {
                Mode = FilesMode.Decrypt;
                ExtractArchive = summary.IsArchive;
                UsePassphraseForDecrypt = summary.IsPassphraseMode;
                OutputPath = DeriveDecryptOutputPath(path, summary.IsArchive);
            }
            else
            {
                Mode = FilesMode.Encrypt;
                OutputPath = path + ".shroud";
            }
        }

        RefreshContacts();
        ((AsyncRelayCommand)RunCommand).RaiseCanExecuteChanged();
    }

    public void ClearInput()
    {
        InputPath = null;
        RaisePropertyChanged(nameof(HasInput));
        Mode = FilesMode.None;
        Summary = null;
        OutputPath = null;
        Result = null;
        AwaitingForceConfirmation = false;
    }

    private const string ContainerExtension = ".shroud";

    private string SuggestedOutputName()
    {
        var name = Path.GetFileName(InputPath) ?? "output";
        return Mode == FilesMode.Encrypt ? name + ContainerExtension : StripShroudExtension(name);
    }

    private static string StripShroudExtension(string name) =>
        name.EndsWith(ContainerExtension, StringComparison.OrdinalIgnoreCase)
            ? name[..^ContainerExtension.Length]
            : name + ".out";

    private static string DeriveDecryptOutputPath(string containerPath, bool isArchive)
    {
        var directory = Path.GetDirectoryName(containerPath) ?? "";
        var stripped = StripShroudExtension(Path.GetFileName(containerPath));
        return Path.Combine(directory, stripped);
    }

    private void RefreshContacts()
    {
        Contacts.Clear();
        foreach (var contact in _workspace.Contacts.All())
            Contacts.Add(contact);
    }

    // ---- running the operation -----------------------------------------------------------------

    /// <summary>Awaitable form of ReplaceCommand, for tests -- RelayCommand.Execute is synchronous
    /// and cannot itself return the retry's Task.</summary>
    internal Task RetryWithForceAsync()
    {
        _forceNext = true;
        return RunAsync();
    }

    /// <summary>Internal (not private) so tests can await the real operation directly --
    /// AsyncRelayCommand.Execute is `async void` and cannot be awaited from a test.</summary>
    internal async Task RunAsync()
    {
        Result = null;
        AwaitingForceConfirmation = false;
        IsBusy = true;
        Progress = 0;
        BusyLabel = Mode == FilesMode.Encrypt
            ? "Encrypting"
            : Summary is { IsSigned: true } ? "Decrypting and verifying" : "Decrypting";

        // Captures the UI thread's SynchronizationContext now, on the UI thread, so Report() calls
        // from the background Task.Run below marshal back automatically.
        var progress = new Progress<double>(p => Progress = p);
        _cts = new CancellationTokenSource();
        bool force = _forceNext;
        _forceNext = false;

        try
        {
            if (Mode == FilesMode.Encrypt)
                await RunEncryptAsync(progress, force, _cts.Token);
            else if (Mode == FilesMode.Decrypt)
                await RunDecryptAsync(progress, force, _cts.Token);
        }
        catch (OperationCanceledException)
        {
            Result = new ResultBanner("neutral", "Cancelled", "Nothing was written.");
        }
        catch (ShroudSignatureException ex)
        {
            Result = new ResultBanner("bad", "Wrong sender", $"{ex.Message} Treat this file as hostile.");
        }
        catch (ShroudArchiveException ex)
        {
            Result = new ResultBanner("bad", "Refused", $"{ex.Message} This archive tried to write outside the folder you chose.");
        }
        catch (ShroudFormatException ex)
        {
            Result = new ResultBanner("bad", "Damaged", $"{ex.Message} Nothing was written.");
        }
        catch (ShroudWorkspaceException ex)
        {
            AwaitingForceConfirmation = true;
            Result = new ResultBanner("neutral", "Already exists", ex.Message);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Result = new ResultBanner("neutral", "Couldn't read that", ex.Message);
        }
        finally
        {
            IsBusy = false;
            _cts.Dispose();
            _cts = null;
        }
    }

    private async Task RunEncryptAsync(IProgress<double> progress, bool force, CancellationToken token)
    {
        ShroudPublicKey? recipient = null;

        if (!UsePassphraseForEncrypt)
        {
            recipient = SelectedRecipient?.Key
                ?? (RecipientKeyFilePath is { } path ? ShroudPublicKey.Parse(File.ReadAllText(path)) : null);
        }

        var sender = SignAsMe && HasIdentity ? LoadIdentitySecretKey() : null;
        var passphrase = UsePassphraseForEncrypt ? EncryptPassphrase : null;

        var request = new EncryptRequest(InputPath!, OutputPath!, recipient, passphrase, sender, force);
        await Task.Run(() => _engine.Encrypt(request, progress, token), token);

        Result = new ResultBanner("good", "Protected", $"Wrote {OutputPath}.");
    }

    private async Task RunDecryptAsync(IProgress<double> progress, bool force, CancellationToken token)
    {
        var key = UsePassphraseForDecrypt ? null : LoadIdentitySecretKey();
        var passphrase = UsePassphraseForDecrypt ? DecryptPassphrase : null;
        var expectedSender = SelectedExpectedSender?.Key;

        var request = new DecryptRequest(
            InputPath!, OutputPath!, key, passphrase, expectedSender,
            RequireSigned: false, ExtractArchive, force);

        var report = await Task.Run(() => _engine.Decrypt(request, progress, token), token);

        var (variant, lead) = BannerMapping.ForBanner(report.Standing);
        Result = new ResultBanner(variant, lead, DescribeStanding(report));
    }

    private ShroudSecretKey LoadIdentitySecretKey()
    {
        var text = File.ReadAllText(_workspace.IdentityKeyPath);
        var passphrase = IdentityPassphrase;
        return ShroudSecretKey.Parse(text, () => passphrase);
    }

    private static string DescribeStanding(SignatureReport report) => report.Standing switch
    {
        SignatureStanding.ExpectedSender =>
            $"From {report.Contact?.ToString() ?? report.Fingerprint}, exactly who you expected. The contents are intact and were addressed to you.",
        SignatureStanding.VerifiedContact =>
            $"Signed by {report.Contact}, a contact whose fingerprint you checked.",
        SignatureStanding.SignedByUnknownKey =>
            $"Signed by {report.Fingerprint}, which is not one of your contacts. Anyone can generate a key and sign with it, so this does not tell you who sent it.",
        SignatureStanding.Unsigned =>
            "Nothing establishes who produced this file.",
        _ => throw new ArgumentOutOfRangeException(nameof(report)),
    };
}
