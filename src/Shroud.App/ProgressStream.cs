namespace Shroud.App;

/// <summary>
/// Wraps the input side of an operation to report progress and honour cancellation.
///
/// <c>ShroudFile</c> takes no CancellationToken and reports no progress, and adding either would
/// change a public signature in the format library for the sake of a UI. Wrapping the stream gets
/// both without touching Shroud.Core: every chunk the encryptor or decryptor consumes comes through
/// Read, so that is where the count is taken and where cancellation is observed.
///
/// Cancelling throws out of Read, which unwinds through ShroudFile into the caller's catch. The
/// staging file is removed there (FileOperations.WithStaging), so a cancelled operation leaves
/// nothing behind -- the same path a failure takes.
/// </summary>
internal sealed class ProgressStream(
    Stream inner,
    long totalLength,
    IProgress<double>? progress,
    CancellationToken token) : Stream
{
    private long _read;
    private int _lastReported = -1;

    public override int Read(byte[] buffer, int offset, int count)
    {
        token.ThrowIfCancellationRequested();

        int n = inner.Read(buffer, offset, count);
        _read += n;

        if (progress is not null && totalLength > 0)
        {
            // Report at most 100 times: a 1 MiB chunk on a 10 GB file is 10,000 callbacks, and
            // each one marshals to the UI thread.
            int percent = (int)(_read * 100 / totalLength);
            if (percent != _lastReported)
            {
                _lastReported = percent;
                progress.Report(percent / 100.0);
            }
        }

        return n;
    }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => totalLength;
    public override long Position { get => _read; set => throw new NotSupportedException(); }
    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
