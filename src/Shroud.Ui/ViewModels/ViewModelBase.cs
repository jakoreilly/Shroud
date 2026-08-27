using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace Shroud.Ui.ViewModels;

/// <summary>
/// Minimal hand-rolled INotifyPropertyChanged base. This repo has no DI container and no MVVM
/// toolkit dependency anywhere else, so this stays a small, auditable primitive rather than a
/// package pulled in for one interface.
/// </summary>
public abstract class ViewModelBase : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    protected bool SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
            return false;

        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        return true;
    }

    protected void RaisePropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
