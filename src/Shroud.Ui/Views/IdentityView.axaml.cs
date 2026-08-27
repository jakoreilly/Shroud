using Avalonia.Controls;
using Shroud.Ui.ViewModels;

namespace Shroud.Ui.Views;

public partial class IdentityView : UserControl
{
    public IdentityView()
    {
        InitializeComponent();
        DataContextChanged += (_, _) => WireClipboard();
    }

    private void WireClipboard()
    {
        if (DataContext is not IdentityViewModel vm)
            return;

        vm.ClipboardWriter = text =>
        {
            var clipboard = TopLevel.GetTopLevel(this)?.Clipboard;
            return clipboard?.SetTextAsync(text) ?? Task.CompletedTask;
        };
    }
}
