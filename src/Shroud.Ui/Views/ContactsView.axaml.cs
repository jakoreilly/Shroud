using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using Shroud.App;
using Shroud.Ui.ViewModels;

namespace Shroud.Ui.Views;

public partial class ContactsView : UserControl
{
    public ContactsView()
    {
        InitializeComponent();
        DataContextChanged += (_, _) => WireFilePicker();
    }

    private void WireFilePicker()
    {
        if (DataContext is not ContactsViewModel vm)
            return;

        vm.KeyFilePicker = async () =>
        {
            var storage = TopLevel.GetTopLevel(this)?.StorageProvider;
            if (storage is null)
                return null;

            var files = await storage.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = "Their public key file",
                AllowMultiple = false,
                FileTypeFilter = [new FilePickerFileType("Public key") { Patterns = ["*.pub"] }],
            });

            return files.Count > 0 ? files[0].TryGetLocalPath() : null;
        };
    }

    private async void OnBrowseClick(object? sender, RoutedEventArgs e)
    {
        if (DataContext is ContactsViewModel vm)
            await vm.BrowseForKeyFileAsync();
    }

    private void OnRemoveClick(object? sender, RoutedEventArgs e)
    {
        if (sender is Button { DataContext: Contact contact } && DataContext is ContactsViewModel vm)
            vm.RemoveCommand.Execute(contact);
    }
}
