using Shroud.App;

namespace Shroud.App.Tests;

public sealed class ProgressStreamTests
{
    [Fact]
    public void Read_ReportsProgressMonotonically()
    {
        var data = new byte[10_000];
        var reported = new List<double>();
        var progress = new SynchronousProgress<double>(reported.Add);

        using var inner = new MemoryStream(data);
        using var stream = new ProgressStream(inner, data.Length, progress, CancellationToken.None);

        var buffer = new byte[1_000];
        while (stream.Read(buffer, 0, buffer.Length) > 0)
        {
        }

        Assert.NotEmpty(reported);
        Assert.Equal(reported, reported.OrderBy(x => x));
        Assert.Equal(1.0, reported[^1]);
    }

    [Fact]
    public void Read_ThrowsWhenTheTokenIsAlreadyCancelled()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        using var inner = new MemoryStream([1, 2, 3]);
        using var stream = new ProgressStream(inner, inner.Length, progress: null, cts.Token);

        var buffer = new byte[10];
        Assert.Throws<OperationCanceledException>(() => stream.Read(buffer, 0, buffer.Length));
    }

    [Fact]
    public void NonSeekable_RejectsSeekAndWrite()
    {
        using var inner = new MemoryStream([1, 2, 3]);
        using var stream = new ProgressStream(inner, inner.Length, progress: null, CancellationToken.None);

        Assert.False(stream.CanSeek);
        Assert.False(stream.CanWrite);
        Assert.Throws<NotSupportedException>(() => stream.Seek(0, SeekOrigin.Begin));
        Assert.Throws<NotSupportedException>(() => stream.Write([1], 0, 1));
    }

    /// <summary>A synchronous stand-in for <c>Progress&lt;T&gt;</c>, which posts to a
    /// SynchronizationContext that does not exist in a unit test.</summary>
    private sealed class SynchronousProgress<T>(Action<T> callback) : IProgress<T>
    {
        public void Report(T value) => callback(value);
    }
}
