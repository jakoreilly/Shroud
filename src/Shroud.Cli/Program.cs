using Shroud.App;
using Shroud.Core;

namespace Shroud.Cli;

internal static class Program
{
    private const string FilePassphraseEnvVar = "SHROUD_PASSPHRASE";

    private const string KeyPassphraseEnvVar = "SHROUD_KEY_PASSPHRASE";

    // A property, not a cached field: SHROUD_HOME can change between commands within one process (the
    // CLI test suite does exactly this), and ShroudWorkspace.FromEnvironment() must observe that.
    private static ShroudWorkspace Workspace => ShroudWorkspace.FromEnvironment();

    public static int Main(string[] args)
    {
        try
        {
            return Run(args);
        }
        catch (ShroudSignatureException ex)
        {
            Console.Error.WriteLine($"shroud: SIGNATURE: {ex.Message}");
            return 3;
        }
        catch (ShroudArchiveException ex)
        {
            // A hostile archive is a bad container, not a usage problem.
            Console.Error.WriteLine($"shroud: ARCHIVE: {ex.Message}");
            return 2;
        }
        catch (ShroudFormatException ex)
        {
            Console.Error.WriteLine($"shroud: {ex.Message}");
            return 2;
        }
        catch (ShroudWorkspaceException ex)
        {
            Console.Error.WriteLine($"shroud: {ex.Message}");
            Console.Error.WriteLine("Run 'shroud --help' for usage.");
            return 64;
        }
        catch (UsageException ex)
        {
            Console.Error.WriteLine($"shroud: {ex.Message}");
            Console.Error.WriteLine("Run 'shroud --help' for usage.");
            return 64;
        }
        catch (ArgumentException ex)
        {
            // Options are validated as they are parsed, so this is a backstop: a library
            // precondition that the option checks did not already cover is still the caller
            // passing something unusable, not an internal fault worth a stack trace.
            Console.Error.WriteLine($"shroud: {ex.Message}");
            Console.Error.WriteLine("Run 'shroud --help' for usage.");
            return 64;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // UnauthorizedAccessException is not an IOException: a directory passed as --in, or a
            // file the user cannot read, arrives here and is an I/O failure like any other.
            Console.Error.WriteLine($"shroud: {ex.Message}");
            return 74;
        }
    }

    private static int Run(string[] args)
    {
        if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
        {
            PrintUsage();
            return args.Length == 0 ? 64 : 0;
        }

        if (args[0] == "contacts")
            return ContactsCommand(args);

        var options = Options.Parse(args[1..]);

        return args[0] switch
        {
            "keygen" => KeyGen(options),
            "encrypt" => Encrypt(options),
            "decrypt" => Decrypt(options),
            "verify" => Verify(options),
            "info" => Info(options),
            "passwd" => Passwd(options),
            "fingerprint" => Fingerprint(options),
            _ => throw new UsageException($"Unknown command '{args[0]}'."),
        };
    }

    private static int KeyGen(Options options)
    {
        // With no --out this writes the identity shroud uses by default, which is what makes
        // `shroud keygen` on a new machine enough to get started.
        bool isDefaultIdentity = options.Output is null;

        if (isDefaultIdentity)
            Workspace.EnsureExists();

        var secretPath = isDefaultIdentity ? Workspace.IdentityKeyPath : options.Output + ".key";
        var publicPath = isDefaultIdentity ? Workspace.IdentityPublicPath : options.Output + ".pub";

        foreach (var path in new[] { secretPath, publicPath })
        {
            if (File.Exists(path) && !options.Force)
                throw new UsageException($"{path} already exists. Pass --force to overwrite.");
        }

        string? passphrase = options.PlaintextKey ? null : ReadKeyPassphrase(options, confirm: true);
        var result = IdentityService.CreateAt(secretPath, publicPath, passphrase, options.Force);
        var protection = result.Protected ? "Argon2id + AES-256-GCM" : "UNENCRYPTED";

        Console.WriteLine($"secret key:  {secretPath} ({protection})");
        Console.WriteLine($"public key:  {publicPath}");
        Console.WriteLine($"fingerprint: {result.Fingerprint}");

        if (options.PlaintextKey)
            Console.Error.WriteLine("shroud: warning: secret key written without a passphrase (--plaintext-key).");

        Console.WriteLine();

        if (isDefaultIdentity)
            Console.WriteLine("This is now your default identity: shroud signs with it unless you pass --no-sign.");

        Console.WriteLine("Back up the secret key now. There is no recovery if you lose it.");
        Console.WriteLine("Share the fingerprint over a channel separate from the .pub file, so the");
        Console.WriteLine("other side can confirm the key they received is the key you sent.");
        return 0;
    }

    private static int Encrypt(Options options)
    {
        if (options.RecipientPath is null && !options.UsePassphrase)
            throw new UsageException("encrypt needs either --recipient <file.pub> or --passphrase.");

        var inputPath = options.Input ?? throw new UsageException("Missing --in <file>.");
        var outputPath = options.Output ?? throw new UsageException("Missing --out <file>.");

        FileOperations.RefuseExistingFile(outputPath, options.Force);

        // A directory becomes a tar archive first. The tar is written beside the output so it
        // lands on the volume the user chose, and it is removed however this ends.
        bool isDirectory = Directory.Exists(inputPath);
        var archivePath = isDirectory ? outputPath + ".shroud-archive" : null;

        try
        {
            if (archivePath is not null)
            {
                using (var tar = File.Create(archivePath))
                {
                    int packed = Archive.CreateFrom(inputPath, tar);
                    Console.Error.WriteLine($"shroud: packed {packed} entries from {inputPath}");
                }

                inputPath = archivePath;
            }

            var sender = ResolveSender(options);

            if (sender is not null)
                Console.Error.WriteLine($"shroud: signing as {Describe(sender.GetPublicKey())}");

            FileOperations.WithStaging(inputPath, outputPath, options.Force, (input, output) =>
            {
                if (options.RecipientPath is not null)
                {
                    var recipient = ResolvePublicKey(options.RecipientPath, "recipient");
                    ShroudFile.Encrypt(input, output, recipient, sender, options.ChunkSizeLog, isDirectory);
                }
                else
                {
                    var passphrase = ReadFilePassphrase(options, confirm: true);
                    ShroudFile.EncryptWithPassphrase(
                        input,
                        output,
                        passphrase,
                        sender,
                        chunkSizeLog: options.ChunkSizeLog,
                        archive: isDirectory);
                }
            });

            return 0;
        }
        finally
        {
            if (archivePath is not null)
                FileOperations.TryDelete(archivePath);
        }
    }

    private static int Decrypt(Options options)
    {
        if (options.KeyPath is null && !options.UsePassphrase)
            throw new UsageException("decrypt needs either --key <file.key> or --passphrase.");

        var inputPath = options.Input ?? throw new UsageException("Missing --in <file>.");
        var outputPath = options.Output ?? throw new UsageException("Missing --out <file>.");

        var policy = BuildPolicy(options);
        DecryptionResult? result = null;

        FileOperations.WithStaging(
            inputPath,
            outputPath,
            options.Force,
            (input, output) =>
            {
                if (options.KeyPath is not null)
                {
                    var secretKey = LoadSecretKey(options.KeyPath, options);
                    result = ShroudFile.Decrypt(input, output, secretKey, policy);
                }
                else
                {
                    var passphrase = ReadFilePassphrase(options, confirm: false);
                    result = ShroudFile.DecryptWithPassphrase(input, output, passphrase, policy);
                }
            },
            complete: (staging, destination) =>
            {
                // Unpacking happens only here, after the whole container -- signature included --
                // has verified. Nothing unverified is ever written into the destination tree.
                if (result is { IsArchive: true } && !options.NoExtract)
                {
                    FileOperations.RefuseNonEmptyDirectory(destination, options.Force);

                    using (var tar = File.OpenRead(staging))
                    {
                        int extracted = Archive.ExtractTo(tar, destination);
                        Console.Error.WriteLine($"shroud: extracted {extracted} files into {destination}");
                    }

                    File.Delete(staging);
                    return;
                }

                File.Move(staging, destination, overwrite: true);
            });

        ReportSignature(result);
        return 0;
    }

    private static int Verify(Options options)
    {
        if (options.KeyPath is null && !options.UsePassphrase)
            throw new UsageException("verify needs either --key <file.key> or --passphrase.");

        var inputPath = options.Input ?? throw new UsageException("verify needs --in <file>.");
        var policy = BuildPolicy(options);

        // Verification has to decrypt -- the signature is inside the encrypted region -- but the
        // plaintext is discarded rather than written anywhere.
        using var input = File.OpenRead(inputPath);

        var result = options.KeyPath is not null
            ? ShroudFile.Decrypt(input, Stream.Null, LoadSecretKey(options.KeyPath, options), policy)
            : ShroudFile.DecryptWithPassphrase(input, Stream.Null, ReadFilePassphrase(options, confirm: false), policy);

        ReportSignature(result);
        Console.WriteLine($"{inputPath}: intact, {(result.IsArchive ? "directory archive" : "single file")}");
        return 0;
    }

    private static int Info(Options options)
    {
        var path = options.Input ?? throw new UsageException("info needs --in <file>.");
        using var input = File.OpenRead(path);
        var header = ShroudFile.ReadHeader(input);

        var mode = header.Mode == ShroudFormat.ModeRecipient
            ? "recipient (ML-KEM-768 + X25519)"
            : "passphrase (Argon2id)";

        Console.WriteLine($"format:      Shroud v{ShroudFormat.Version}");
        Console.WriteLine($"mode:        {mode}");
        Console.WriteLine("suite:       HKDF-SHA256, AES-256-GCM");
        Console.WriteLine($"signed:      {(header.IsSigned ? "yes (ML-DSA-65)" : "no")}");
        Console.WriteLine($"content:     {(header.IsArchive ? "directory archive (tar)" : "single file")}");
        Console.WriteLine($"chunk size:  {header.ChunkSize / 1024} KiB");

        if (header.Argon2 is { } argon)
            Console.WriteLine($"argon2id:    t={argon.Iterations} m={argon.MemoryKib}KiB p={argon.Lanes}");

        // The sender's identity lives inside the encrypted region, so it is deliberately not
        // reported here -- that is a privacy property, not an omission.
        if (header.IsSigned)
            Console.WriteLine("sender:      encrypted (decrypt or verify to establish it)");

        return 0;
    }

    private static int Passwd(Options options)
    {
        var path = options.KeyPath ?? options.Input
            ?? (Workspace.HasIdentity ? Workspace.IdentityKeyPath : null)
            ?? throw new UsageException("passwd needs --key <file.key>.");

        var text = File.ReadAllText(path);
        var secretKey = LoadSecretKeyFromText(text, path, options);

        string? passphrase;
        string protection;

        if (options.PlaintextKey)
        {
            passphrase = null;
            protection = "UNENCRYPTED";
        }
        else
        {
            Console.Error.WriteLine("Enter the NEW passphrase for this key file.");
            passphrase = PromptTwice("New passphrase: ", "Confirm new passphrase: ");
            protection = "Argon2id + AES-256-GCM";
        }

        var fingerprint = secretKey.GetPublicKey().Fingerprint();

        // Write beside the original and swap, so an interrupted run cannot lose the only copy.
        var temporary = path + ".new";
        KeyFiles.WriteSecretKey(temporary, secretKey, passphrase, fingerprint);
        File.Move(temporary, path, overwrite: true);

        Console.WriteLine($"{path}: protection now {protection}");
        return 0;
    }

    private static int Fingerprint(Options options)
    {
        var path = options.Input ?? options.RecipientPath ?? options.KeyPath
            ?? (Workspace.HasIdentity ? Workspace.IdentityPublicPath : null)
            ?? throw new UsageException("fingerprint needs --in <file.pub or file.key>.");

        // A bare name is looked up as a contact, so `shroud fingerprint --in bob` works.
        if (!File.Exists(path) && Workspace.Contacts.ByName(path) is { } contact)
        {
            Console.WriteLine(contact.Fingerprint);
            return 0;
        }

        var text = File.ReadAllText(path);

        var key = text.Contains(":v2:", StringComparison.Ordinal) && text.Contains("recipient", StringComparison.Ordinal)
            ? ShroudPublicKey.Parse(text)
            : LoadSecretKeyFromText(text, path, options).GetPublicKey();

        Console.WriteLine(key.Fingerprint());
        return 0;
    }

    // ---- contacts ---------------------------------------------------------------------------

    private static int ContactsCommand(string[] args)
    {
        var subcommand = args.Length > 1 ? args[1] : "list";
        var options = Options.Parse(args.Length > 2 ? args[2..] : []);

        return subcommand switch
        {
            "list" => ContactsList(),
            "add" => ContactsAdd(options),
            "remove" or "rm" => ContactsRemove(options),
            _ => throw new UsageException($"Unknown contacts subcommand '{subcommand}'. Use list, add or remove."),
        };
    }

    private static int ContactsList()
    {
        var contacts = Workspace.Contacts.All();

        if (contacts.Count == 0)
        {
            Console.WriteLine("No contacts yet.");
            Console.WriteLine("Add one with: shroud contacts add --in bob.pub --name bob --fingerprint <their fingerprint>");
            return 0;
        }

        foreach (var contact in contacts)
            Console.WriteLine($"{contact.Name,-24} {contact.Fingerprint}");

        return 0;
    }

    private static int ContactsAdd(Options options)
    {
        var path = options.Input ?? options.RecipientPath
            ?? throw new UsageException("contacts add needs --in <file.pub>.");
        var name = options.Name ?? throw new UsageException("contacts add needs --name <name>.");

        var expected = options.Fingerprint ?? throw new UsageException(
            "contacts add needs --fingerprint <fingerprint>. Get it from the other person over a "
                + "channel the key did not travel on, and type it in. That comparison is what makes "
                + "the contact mean anything.");

        var key = ShroudPublicKey.Parse(File.ReadAllText(path));
        Workspace.Contacts.Add(name, key, expected, options.Force);

        Console.WriteLine($"added contact {name} ({key.Fingerprint()})");
        return 0;
    }

    private static int ContactsRemove(Options options)
    {
        var name = options.Name ?? options.Input
            ?? throw new UsageException("contacts remove needs --name <name>.");

        if (!Workspace.Contacts.Remove(name))
            throw new UsageException($"No contact named '{name}'.");

        Console.WriteLine($"removed contact {name}");
        return 0;
    }

    // ---- shared plumbing --------------------------------------------------------------------

    private static VerificationPolicy BuildPolicy(Options options)
    {
        if (options.SenderPath is not null)
            return VerificationPolicy.From(ResolvePublicKey(options.SenderPath, "sender"));

        return options.RequireSigned ? VerificationPolicy.Required : VerificationPolicy.Optional;
    }

    /// <summary>
    /// Resolves a public key given either a path or the name of a contact. A name is only ever
    /// reported alongside its fingerprint: names are chosen by whoever made the key, fingerprints
    /// are not.
    /// </summary>
    private static ShroudPublicKey ResolvePublicKey(string value, string role)
    {
        if (File.Exists(value))
            return ShroudPublicKey.Parse(File.ReadAllText(value));

        if (Workspace.Contacts.ByName(value) is { } contact)
        {
            Console.Error.WriteLine($"shroud: {role} {contact}");
            return contact.Key;
        }

        throw new UsageException(
            $"No file or contact named '{value}'. List what you have with 'shroud contacts list'.");
    }

    /// <summary>The identity to sign with: an explicit --sign, otherwise the default identity.</summary>
    private static ShroudSecretKey? ResolveSender(Options options)
    {
        if (options.NoSign)
            return null;

        if (options.SignKeyPath is not null)
            return LoadSecretKey(options.SignKeyPath, options);

        return Workspace.HasIdentity ? LoadSecretKey(Workspace.IdentityKeyPath, options) : null;
    }

    /// <summary>
    /// Prints what a decryption established about origin. Switches on the four
    /// <see cref="SignatureStanding"/> cases so a fifth case added there is a compile error here,
    /// not a silently-missing branch.
    /// </summary>
    private static void ReportSignature(DecryptionResult? result)
    {
        if (result is null)
            return;

        var report = SignatureReport.For(result, Workspace);

        switch (report.Standing)
        {
            case SignatureStanding.Unsigned:
                Console.Error.WriteLine("shroud: container is UNSIGNED -- nothing establishes who produced it.");
                break;

            case SignatureStanding.ExpectedSender:
                Console.Error.WriteLine(
                    $"shroud: signature OK, from the expected sender {report.Contact?.ToString() ?? report.Fingerprint}");
                break;

            case SignatureStanding.VerifiedContact:
                // Matching a contact is exactly as strong as naming one: it is the same key you
                // confirmed the fingerprint of when you added them.
                Console.Error.WriteLine($"shroud: signature OK, from your verified contact {report.Contact}");
                break;

            case SignatureStanding.SignedByUnknownKey:
                // A valid signature from an unknown key proves only self-consistency: anyone can
                // generate a key and sign. Say so rather than printing a reassuring tick.
                Console.Error.WriteLine($"shroud: signature is internally valid, signed by {report.Fingerprint}");
                Console.Error.WriteLine(
                    "shroud: warning: sender identity NOT checked -- that key is not one of your contacts.");
                break;
        }
    }

    private static string Describe(ShroudPublicKey key) =>
        Workspace.Contacts.ByKey(key)?.ToString() ?? key.Fingerprint();

    private static ShroudSecretKey LoadSecretKey(string path, Options options) =>
        LoadSecretKeyFromText(File.ReadAllText(path), path, options);

    private static ShroudSecretKey LoadSecretKeyFromText(string text, string path, Options options)
    {
        // The passphrase callback is only invoked for protected files, so an unprotected key
        // never triggers a prompt.
        return ShroudSecretKey.Parse(text, () =>
        {
            Console.Error.WriteLine($"Key file {path} is passphrase-protected.");
            return ReadKeyPassphrase(options, confirm: false);
        });
    }

    private static string ReadFilePassphrase(Options options, bool confirm) =>
        ReadPassphrase(options.PassphraseFile, FilePassphraseEnvVar, confirm, "Passphrase: ");

    private static string ReadKeyPassphrase(Options options, bool confirm) =>
        ReadPassphrase(options.KeyPassphraseFile, KeyPassphraseEnvVar, confirm, "Key passphrase: ");

    private static string ReadPassphrase(string? file, string envVar, bool confirm, string label)
    {
        if (file is not null)
        {
            var fromFile = File.ReadAllText(file).TrimEnd('\r', '\n');
            if (fromFile.Length == 0)
                throw new UsageException($"{file} is empty.");
            return fromFile;
        }

        var fromEnv = Environment.GetEnvironmentVariable(envVar);
        if (!string.IsNullOrEmpty(fromEnv))
            return fromEnv;

        if (Console.IsInputRedirected)
            throw new UsageException($"No console available. Use a passphrase file or set {envVar}.");

        return confirm
            ? PromptTwice(label, "Confirm: ")
            : Prompt(label);
    }

    private static string PromptTwice(string first, string second)
    {
        var passphrase = Prompt(first);
        if (passphrase.Length == 0)
            throw new UsageException("Passphrase must not be empty.");
        if (Prompt(second) != passphrase)
            throw new UsageException("Passphrases did not match.");

        return passphrase;
    }

    private static string Prompt(string label)
    {
        Console.Error.Write(label);
        var buffer = new System.Text.StringBuilder();

        while (true)
        {
            var key = Console.ReadKey(intercept: true);

            if (key.Key == ConsoleKey.Enter)
                break;

            if (key.Key == ConsoleKey.Backspace)
            {
                if (buffer.Length > 0)
                    buffer.Length--;
                continue;
            }

            if (!char.IsControl(key.KeyChar))
                buffer.Append(key.KeyChar);
        }

        Console.Error.WriteLine();
        return buffer.ToString();
    }

    private static void PrintUsage()
    {
        Console.WriteLine(
            """
            shroud - post-quantum file encryption
                  ML-KEM-768 + X25519 key wrapping, ML-DSA-65 signatures, AES-256-GCM payload

            USAGE
              shroud keygen        [--out <basename>] [--plaintext-key]
              shroud encrypt       --in <f|dir> --out <f> (--recipient <name|f.pub> | --passphrase)
              shroud decrypt       --in <f> --out <f|dir> (--key <f.key> | --passphrase) [--sender <name|f.pub>]
              shroud verify        --in <f> (--key <f.key> | --passphrase) [--sender <name|f.pub>]
              shroud info          --in <f>
              shroud contacts      list | add --in <f.pub> --name <n> --fingerprint <fp> | remove --name <n>
              shroud passwd        [--key <f.key>] [--plaintext-key]
              shroud fingerprint   --in <name|f.pub|f.key>

            OPTIONS
              -i, --in <path>              Input file, directory, or contact name
              -o, --out <path>             Output file, or basename for keygen
              -r, --recipient <name|path>  Contact name, or public key file, to encrypt to
              -k, --key <path>             Secret key to decrypt with
              -p, --passphrase             Use passphrase mode for the FILE
                  --passphrase-file <p>    Read the file passphrase from a file
                  --key-passphrase-file <p> Read the KEY passphrase from a file
              -s, --sign <path>            Sign as this identity (default: your identity, if any)
                  --no-sign                Do not sign, even if you have a default identity
                  --sender <name|path>     Require the signature to be from this identity
                  --require-signed         Reject unsigned containers
                  --name <name>            Contact name, for the contacts command
                  --fingerprint <fp>       Fingerprint you verified out of band, for contacts add
                  --no-extract             Write the raw tar instead of unpacking a directory
                  --plaintext-key          Write the secret key without a passphrase
                  --chunk-size-log <n>     Log2 of the chunk size, 12-26 (default 20 = 1 MiB)
              -f, --force                  Overwrite existing output

            Passphrases may also come from SHROUD_PASSPHRASE (files) and SHROUD_KEY_PASSPHRASE (keys).
            Your identity and contacts live in SHROUD_HOME, or ~/.shroud by default.

            EXIT CODES
              0 ok   2 bad container   3 signature problem   64 usage   74 I/O

            EXAMPLES
              shroud keygen                                          # set up this machine
              shroud contacts add --in bob.pub --name bob --fingerprint d83c9fbfed01dd22
              shroud encrypt --in ./records --out records.shroud --recipient bob
              shroud decrypt --in records.shroud --out ./records --key ~/.shroud/identity.key
              shroud verify  --in records.shroud --key ~/.shroud/identity.key --sender bob

            A signature only tells you who sent a file if the signing key is one you have checked.
            Add people as contacts and shroud will name them for you; an unknown key is reported as
            unknown, never as a silent success.
            """);
    }
}

internal sealed class UsageException(string message) : Exception(message);

internal sealed class Options
{
    public string? Input { get; private set; }

    public string? Output { get; private set; }

    public string? RecipientPath { get; private set; }

    public string? KeyPath { get; private set; }

    public string? SignKeyPath { get; private set; }

    public string? SenderPath { get; private set; }

    public string? PassphraseFile { get; private set; }

    public string? KeyPassphraseFile { get; private set; }

    public string? Name { get; private set; }

    public string? Fingerprint { get; private set; }

    public bool UsePassphrase { get; private set; }

    public bool RequireSigned { get; private set; }

    public bool NoSign { get; private set; }

    public bool NoExtract { get; private set; }

    public bool PlaintextKey { get; private set; }

    public bool Force { get; private set; }

    public byte ChunkSizeLog { get; private set; } = ShroudFormat.DefaultChunkSizeLog;

    public static Options Parse(string[] args)
    {
        var options = new Options();

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "-i" or "--in":
                    options.Input = Next(args, ref i);
                    break;

                case "-o" or "--out":
                    options.Output = Next(args, ref i);
                    break;

                case "-r" or "--recipient":
                    options.RecipientPath = Next(args, ref i);
                    break;

                case "-k" or "--key":
                    options.KeyPath = Next(args, ref i);
                    break;

                case "-s" or "--sign":
                    options.SignKeyPath = Next(args, ref i);
                    break;

                case "--no-sign":
                    options.NoSign = true;
                    break;

                case "--sender":
                    options.SenderPath = Next(args, ref i);
                    options.RequireSigned = true;
                    break;

                case "--require-signed":
                    options.RequireSigned = true;
                    break;

                case "--name":
                    options.Name = Next(args, ref i);
                    break;

                case "--fingerprint":
                    options.Fingerprint = Next(args, ref i);
                    break;

                case "--no-extract":
                    options.NoExtract = true;
                    break;

                case "--passphrase-file":
                    options.PassphraseFile = Next(args, ref i);
                    options.UsePassphrase = true;
                    break;

                case "--key-passphrase-file":
                    options.KeyPassphraseFile = Next(args, ref i);
                    break;

                case "-p" or "--passphrase":
                    options.UsePassphrase = true;
                    break;

                case "--plaintext-key":
                    options.PlaintextKey = true;
                    break;

                case "-f" or "--force":
                    options.Force = true;
                    break;

                case "--chunk-size-log":
                    var raw = Next(args, ref i);
                    if (!byte.TryParse(raw, out var log))
                        throw new UsageException($"--chunk-size-log expects a number, got '{raw}'.");
                    if (log < ShroudFormat.MinChunkSizeLog || log > ShroudFormat.MaxChunkSizeLog)
                    {
                        throw new UsageException(
                            $"--chunk-size-log must be between {ShroudFormat.MinChunkSizeLog} and "
                                + $"{ShroudFormat.MaxChunkSizeLog}, got {log}.");
                    }

                    options.ChunkSizeLog = log;
                    break;

                default:
                    throw new UsageException($"Unknown option '{args[i]}'.");
            }
        }

        if (options.RecipientPath is not null && options.UsePassphrase)
            throw new UsageException("Choose either --recipient or --passphrase, not both.");
        if (options.KeyPath is not null && options.UsePassphrase)
            throw new UsageException("Choose either --key or --passphrase, not both.");
        if (options.SignKeyPath is not null && options.NoSign)
            throw new UsageException("Choose either --sign or --no-sign, not both.");

        return options;
    }

    private static string Next(string[] args, ref int i)
    {
        if (i + 1 >= args.Length)
            throw new UsageException($"Option '{args[i]}' needs a value.");

        var value = args[++i];

        // An empty path reaches the file APIs as an ArgumentException rather than a missing file,
        // so it is caught here where it can still be reported as the option it came from.
        if (value.Length == 0)
            throw new UsageException($"Option '{args[i - 1]}' needs a non-empty value.");

        return value;
    }
}
