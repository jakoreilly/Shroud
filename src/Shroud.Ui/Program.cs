using Avalonia;

namespace Shroud.Ui;

internal static class Program
{
    // Avalonia needs a classic Main, not the top-level statements a WinExe would otherwise use,
    // so BuildAvaloniaApp is reachable separately for design-time tooling and future headless tests.
    [STAThread]
    public static void Main(string[] args) => BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);

    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .LogToTrace();
}
