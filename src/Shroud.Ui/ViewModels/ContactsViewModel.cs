using System.Collections.ObjectModel;
using System.Windows.Input;
using Shroud.App;
using Shroud.Core;

namespace Shroud.Ui.ViewModels;

/// <summary>
/// Drives the Contacts screen: the fingerprint ceremony as a workflow. The fingerprint field
/// starts empty and is never pre-filled from the key file -- <see cref="ContactStore.Add"/> is the
/// only trust decision this tool has, and pre-filling would turn it into a click-through.
/// </summary>
public sealed class ContactsViewModel : ViewModelBase
{
    private readonly ShroudWorkspace _workspace;

    private string? _keyFilePath;
    private string _name = string.Empty;
    private string _fingerprintInput = string.Empty;
    private string? _errorMessage;
    private string? _successMessage;

    public ContactsViewModel(ShroudWorkspace workspace)
    {
        _workspace = workspace;
        AddCommand = new RelayCommand(Add, () => CanAdd);
        RemoveCommand = new RelayCommand<Contact>(Remove);
        Refresh();
    }

    /// <summary>Wired by the view to a file-picker dialog; the view model has no Avalonia types.</summary>
    public Func<Task<string?>>? KeyFilePicker { get; set; }

    public ObservableCollection<Contact> Contacts { get; } = [];

    public bool HasContacts => Contacts.Count > 0;

    public string? KeyFilePath
    {
        get => _keyFilePath;
        private set
        {
            if (SetField(ref _keyFilePath, value))
            {
                RaisePropertyChanged(nameof(CanAdd));
                ((RelayCommand)AddCommand).RaiseCanExecuteChanged();
            }
        }
    }

    public string Name
    {
        get => _name;
        set
        {
            if (SetField(ref _name, value))
            {
                RaisePropertyChanged(nameof(CanAdd));
                RaisePropertyChanged(nameof(NameIsValid));
                ((RelayCommand)AddCommand).RaiseCanExecuteChanged();
            }
        }
    }

    /// <summary>True once the name field has content but is not (yet) usable, so the view can show
    /// the "use letters, digits, dot, dash and underscore" hint without flashing it on an empty
    /// field the user has not touched yet.</summary>
    public bool NameIsValid => Name.Length == 0 || ContactStore.IsValidName(Name);

    public string FingerprintInput
    {
        get => _fingerprintInput;
        set
        {
            if (SetField(ref _fingerprintInput, value))
            {
                RaisePropertyChanged(nameof(CanAdd));
                ((RelayCommand)AddCommand).RaiseCanExecuteChanged();
            }
        }
    }

    public string? ErrorMessage { get => _errorMessage; private set => SetField(ref _errorMessage, value); }

    public string? SuccessMessage { get => _successMessage; private set => SetField(ref _successMessage, value); }

    public bool CanAdd =>
        !string.IsNullOrWhiteSpace(KeyFilePath)
        && ContactStore.IsValidName(Name)
        && FingerprintInput.Trim().Length > 0;

    public ICommand AddCommand { get; }

    public ICommand RemoveCommand { get; }

    public async Task BrowseForKeyFileAsync()
    {
        if (KeyFilePicker is null)
            return;

        var path = await KeyFilePicker();
        if (path is not null)
            KeyFilePath = path;
    }

    private void Refresh()
    {
        Contacts.Clear();
        foreach (var contact in _workspace.Contacts.All())
            Contacts.Add(contact);

        RaisePropertyChanged(nameof(HasContacts));
    }

    private void Add()
    {
        ErrorMessage = null;
        SuccessMessage = null;

        try
        {
            var key = ShroudPublicKey.Parse(File.ReadAllText(KeyFilePath!));
            _workspace.Contacts.Add(Name, key, FingerprintInput, force: false);

            SuccessMessage = $"Added {Name} ({key.Fingerprint()})";
            Name = string.Empty;
            FingerprintInput = string.Empty;
            KeyFilePath = null;
            Refresh();
        }
        catch (Exception ex) when (ex is ShroudWorkspaceException or ShroudFormatException or IOException)
        {
            ErrorMessage = ex.Message;
        }
    }

    private void Remove(Contact? contact)
    {
        if (contact is null)
            return;

        _workspace.Contacts.Remove(contact.Name);
        Refresh();
    }
}
