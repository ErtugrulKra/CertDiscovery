namespace CertificateDiscovery.Infrastructure.Dns;

public static class DnsTxtRecordSetSemantics
{
    public static IReadOnlyList<string> Merge(IEnumerable<string> existing, IEnumerable<string> requested) =>
        existing.Concat(requested).Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.Ordinal).OrderBy(x => x, StringComparer.Ordinal).ToList();

    public static IReadOnlyList<string> RemoveOwned(IEnumerable<string> existing, IEnumerable<string> owned)
    {
        var ownedSet = owned.ToHashSet(StringComparer.Ordinal);
        return existing.Where(x => !ownedSet.Contains(x)).Distinct(StringComparer.Ordinal)
            .OrderBy(x => x, StringComparer.Ordinal).ToList();
    }
}
