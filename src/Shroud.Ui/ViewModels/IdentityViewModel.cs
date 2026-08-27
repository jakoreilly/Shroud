using System.Windows.Input;
using Shroud.App;
using Shroud.Core;

namespace Shroud.Ui.ViewModels;

/// <summary>
/// Drives the Identity screen. Talks to IdentityService/ShroudWorkspace directly rather than through
/// IShroudEngine: creating an identity is workspace-level state, not an encrypt/decrypt operation.
/// </summary>
public sealed class IdentityViewModel : ViewModelBase
{
    private readonly ShroudWorkspace _workspace;

    private bool _hasIdentity;
    private string? _fingerprint;
    private bool _isCreating;
    private bool _justCreated;
    private bool _backupAcknowledged;
    private string _newPassphrase = string.Empty;
    private string _confirmPassphrase = string.Empty;
    private string? _errorMessage;
    private string? _copyFeedback;

    public IdentityViewModel(ShroudWorkspace workspace)
    {
        _workspace = workspace;
        CreateIdentityCommand = new AsyncRelayCommand(CreateIdentityAsync, () => CanCreate);
        AcknowledgeBackupCommand = new RelayCommand(() => BackupAcknowledged = true);
        CopyFingerprintCommand = new RelayCommand(CopyFingerprint, () => Fingerprint is not null);
        Refresh();
    }

    /// <summary>Wired by the view to the platform clipboard; the view model has no Avalonia types.</summary>
    public Func<string, Task>? ClipboardWriter { get; set; }

    public bool HasIdentity { get => _hasIdentity; private set => SetField(ref _hasIdentity, value); }

    public string? Fingerprint { get => _fingerprint; private set => SetField(ref _fingerprint, value); }

    public bool IsCreating { get => _isCreating; private set => SetField(ref _isCreating, value); }

    /// <summary>Shows only in the session that created the identity, not every time the app opens
    /// onto one that already existed.</summary>
    public bool ShowBackupBanner => _justCreated && !_backupAcknowledged;

    public bool BackupAcknowledged
    {
        get => _backupAcknowledged;
        private set
        {
            if (SetField(ref _backupAcknowledged, value))
                RaisePropertyChanged(nameof(ShowBackupBanner));
        }
    }

    public string NewPassphrase
    {
        get => _newPassphrase;
        set
        {
            if (SetField(ref _newPassphrase, value))
            {
                RaisePropertyChanged(nameof(CanCreate));
                ((AsyncRelayCommand)CreateIdentityCommand).RaiseCanExecuteChanged();
            }
        }
    }

    public string ConfirmPassphrase
    {
        get => _confirmPassphrase;
        set
        {
            if (SetField(ref _confirmPassphrase, value))
            {
                RaisePropertyChanged(nameof(CanCreate));
                ((AsyncRelayCommand)CreateIdentityCommand).RaiseCanExecuteChanged();
            }
        }
    }

    public string? ErrorMessage { get => _errorMessage; private set => SetField(ref _errorMessage, value); }

    public string? CopyFeedback { get => _copyFeedback; private set => SetField(ref _copyFeedback, value); }

    public bool CanCreate => NewPassphrase.Length > 0 && NewPassphrase == ConfirmPassphrase;

    public ICommand CreateIdentityCommand { get; }

    public ICommand AcknowledgeBackupCommand { get; }

    public ICommand CopyFingerprintCommand { get; }

    private void Refresh()
    {
        HasIdentity = _workspace.HasIdentity;
        Fingerprint = HasIdentity ? TryReadFingerprint() : null;
    }

    private string? TryReadFingerprint()
    {
        try
        {
            return ShroudPublicKey.Parse(File.ReadAllText(_workspace.IdentityPublicPath)).Fingerprint();
        }
        catch (Exception ex) when (ex is IOException or ShroudFormatException)
        {
            return null;
        }
    }

    private async Task CreateIdentityAsync()
    {
        ErrorMessage = null;
        IsCreating = true;

        try
        {
            var passphrase = NewPassphrase;

            // Argon2id at the default key-file cost is ~1.2s; off the UI thread so the busy
            // overlay stays responsive rather than freezing the window for that whole time.
            var result = await Task.Run(() => IdentityService.CreateDefault(_workspace, passphrase, force: false));

            Fingerprint = result.Fingerprint;
            HasIdentity = true;
            _justCreated = true;
            BackupAcknowledged = false;
            NewPassphrase = string.Empty;
            ConfirmPassphrase = string.Empty;
            RaisePropertyChanged(nameof(ShowBackupBanner));
            ((RelayCommand)CopyFingerprintCommand).RaiseCanExecuteChanged();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ShroudWorkspaceException)
        {
            ErrorMessage = ex.Message;
        }
        finally
        {
            IsCreating = false;
        }
    }

    private void CopyFingerprint()
    {
        if (Fingerprint is null)
            return;

        _ = CopyFingerprintAsync(Fingerprint);
    }

    private async Task CopyFingerprintAsync(string fingerprint)
    {
        if (ClipboardWriter is not null)
            await ClipboardWriter(fingerprint);

        CopyFeedback = "Copied";
        await Task.Delay(2000);

        // Only clear our own feedback: a second copy click within the window should not have its
        // "Copied" erased by the first click's delayed clear.
        if (CopyFeedback == "Copied")
            CopyFeedback = null;
    }
}
