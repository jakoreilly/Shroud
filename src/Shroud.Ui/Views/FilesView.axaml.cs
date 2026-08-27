using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using Shroud.Ui.ViewModels;

namespace Shroud.Ui.Views;

public partial class FilesView : UserControl
{
    public FilesView()
    {
        InitializeComponent();
        DataContextChanged += (_, _) => WirePickers();
    }

    private void WirePickers()
    {
        if (DataContext is not FilesViewModel vm)
            return;

        vm.PickInputFile = () => PickFileAsync("Choose a file");
        vm.PickInputFolder = () => PickFolderAsync("Choose a folder");
        vm.PickRecipientKeyFile = () => PickFileAsync("Their public key file", "*.pub");
        vm.PickOutputFile = suggestedName => SaveFileAsync(suggestedName);
        vm.PickOutputFolder = () => PickFolderAsync("Choose a destination folder");
    }

    private async Task<string?> PickFileAsync(string title, string pattern = "*")
    {
        var storage = TopLevel.GetTopLevel(this)?.StorageProvider;
        if (storage is null)
            return null;

        var files = await storage.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = title,
            AllowMultiple = false,
            FileTypeFilter = [new FilePickerFileType(title) { Patterns = [pattern] }],
        });

        return files.Count > 0 ? files[0].TryGetLocalPath() : null;
    }

    private async Task<string?> PickFolderAsync(string title)
    {
        var storage = TopLevel.GetTopLevel(this)?.StorageProvider;
        if (storage is null)
            return null;

        var folders = await storage.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            Title = title,
            AllowMultiple = false,
        });

        return folders.Count > 0 ? folders[0].TryGetLocalPath() : null;
    }

    private async Task<string?> SaveFileAsync(string suggestedName)
    {
        var storage = TopLevel.GetTopLevel(this)?.StorageProvider;
        if (storage is null)
            return null;

        var file = await storage.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = "Save the container as",
            SuggestedFileName = suggestedName,
        });

        return file?.TryGetLocalPath();
    }

    private async void OnChooseFileClick(object? sender, RoutedEventArgs e)
    {
        if (DataContext is FilesViewModel vm)
            await vm.ChooseInputFileAsync();
    }

    private async void OnChooseFolderClick(object? sender, RoutedEventArgs e)
    {
        if (DataContext is FilesViewModel vm)
            await vm.ChooseInputFolderAsync();
    }

    private void OnChangeInputClick(object? sender, RoutedEventArgs e)
    {
        if (DataContext is FilesViewModel vm)
            vm.ClearInput();
    }

    private async void OnBrowseRecipientClick(object? sender, RoutedEventArgs e)
    {
        if (DataContext is FilesViewModel vm)
            await vm.ChooseRecipientKeyFileAsync();
    }

    private async void OnChooseOutputClick(object? sender, RoutedEventArgs e)
    {
        if (DataContext is FilesViewModel vm)
            await vm.ChooseOutputAsync();
    }

    private void OnDragEnter(object? sender, DragEventArgs e)
    {
        if (sender is Border border && HasFileOrFolder(e))
            border.Classes.Add("dragover");
    }

    private void OnDragLeave(object? sender, RoutedEventArgs e)
    {
        if (sender is Border border)
            border.Classes.Remove("dragover");
    }

    private void OnDrop(object? sender, DragEventArgs e)
    {
        if (sender is Border border)
            border.Classes.Remove("dragover");

        if (DataContext is not FilesViewModel vm)
            return;

        var item = e.DataTransfer.TryGetFiles()?.FirstOrDefault();
        var path = item?.TryGetLocalPath();

        if (path is not null)
            vm.SetInput(path);
    }

    private static bool HasFileOrFolder(DragEventArgs e) => e.DataTransfer.TryGetFiles()?.Length > 0;
}
