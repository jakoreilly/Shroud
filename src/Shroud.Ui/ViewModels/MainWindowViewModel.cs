using Shroud.App;

namespace Shroud.Ui.ViewModels;

/// <summary>
/// Root view model: holds the workspace and engine every screen needs, plus one instance of each
/// screen's view model. There is exactly one of each per running app, not one per navigation to
/// the tab, so state (a contact list, an in-progress passphrase) survives switching tabs and back.
/// </summary>
public sealed class MainWindowViewModel(ShroudWorkspace workspace, IShroudEngine engine) : ViewModelBase
{
    public ShroudWorkspace Workspace { get; } = workspace;

    public IShroudEngine Engine { get; } = engine;

    public IdentityViewModel Identity { get; } = new(workspace);

    public ContactsViewModel Contacts { get; } = new(workspace);

    public FilesViewModel Files { get; } = new(workspace, engine);
}
