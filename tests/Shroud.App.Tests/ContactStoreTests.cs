using Shroud.App;
using Shroud.Core;

namespace Shroud.App.Tests;

public sealed class ContactStoreTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("shroud-app-tests-").FullName;

    public void Dispose() => Directory.Delete(_root, recursive: true);

    private ContactStore NewStore() => new(Path.Combine(_root, "contacts"));

    [Fact]
    public void RoundTrips_AddThenByNameAndAll()
    {
        var store = NewStore();
        var key = ShroudSecretKey.Generate().GetPublicKey();

        store.Add("bob", key, key.Fingerprint(), force: false);

        var byName = store.ByName("bob");
        Assert.NotNull(byName);
        Assert.Equal(key.Fingerprint(), byName!.Fingerprint);

        Assert.Single(store.All());
    }

    [Fact]
    public void ByKey_FindsTheContactHoldingThatExactKey()
    {
        var store = NewStore();
        var key = ShroudSecretKey.Generate().GetPublicKey();
        store.Add("bob", key, key.Fingerprint(), force: false);

        var found = store.ByKey(key);

        Assert.NotNull(found);
        Assert.Equal("bob", found!.Name);
    }

    [Fact]
    public void Add_RefusesAMismatchedFingerprint()
    {
        var store = NewStore();
        var key = ShroudSecretKey.Generate().GetPublicKey();

        Assert.Throws<ShroudWorkspaceException>(() => store.Add("bob", key, "0000000000000000", force: false));
        Assert.Empty(store.All());
    }

    [Fact]
    public void Remove_DeletesAnExistingContact()
    {
        var store = NewStore();
        var key = ShroudSecretKey.Generate().GetPublicKey();
        store.Add("bob", key, key.Fingerprint(), force: false);

        Assert.True(store.Remove("bob"));
        Assert.Null(store.ByName("bob"));
    }

    [Fact]
    public void Remove_ReturnsFalseForAnUnknownContact()
    {
        var store = NewStore();

        Assert.False(store.Remove("nobody"));
    }

    [Theory]
    [InlineData("bob")]
    [InlineData("bob.smith-2")]
    public void IsValidName_AcceptsOrdinaryNames(string name) => Assert.True(ContactStore.IsValidName(name));

    [Theory]
    [InlineData("")]
    [InlineData(".")]
    [InlineData("..")]
    [InlineData("../escape")]
    public void IsValidName_RejectsPathEscapesAndEmptyNames(string name) => Assert.False(ContactStore.IsValidName(name));
}
