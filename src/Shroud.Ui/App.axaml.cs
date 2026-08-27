using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Shroud.App;
using Shroud.Ui.ViewModels;

namespace Shroud.Ui;

public partial class App : Application
{
    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            // No DI container anywhere in this repo (Shroud.Core and Shroud.Cli are all statics), so
            // this is constructed by hand rather than introducing one for the UI alone.
            var workspace = ShroudWorkspace.FromEnvironment();
            var engine = new ShroudEngine(workspace);

            desktop.MainWindow = new MainWindow
            {
                DataContext = new MainWindowViewModel(workspace, engine),
            };
        }

        base.OnFrameworkInitializationCompleted();
    }
}
