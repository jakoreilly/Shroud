namespace Shroud.App;

/// <summary>
/// A request the workspace will not carry out: an existing output that would be overwritten, a
/// contact name that is not usable as a filename, a fingerprint that does not match. These are
/// the caller's problem to report -- the CLI turns them into a usage error, the UI into a message
/// beside the control that caused them.
/// </summary>
public sealed class ShroudWorkspaceException(string message) : Exception(message);
