using Novell.Directory.Ldap;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace ADChecker;

public sealed class ActiveDirectoryClient(LdapSettings settings, string bindPassword)
{
    public async Task TestConnectionAsync()
    {
        using var connection = await ConnectAndBindAsync(settings.BindDn, bindPassword);
        var constraints = CreateSearchConstraints();
        var results = await connection.SearchAsync(
            settings.BaseDn,
            LdapConnection.ScopeBase,
            "(objectClass=*)",
            ["objectClass"],
            false,
            constraints);
        await ReadEntriesAsync(results, 1);
    }

    public async Task<IReadOnlyList<UserRecord>> SearchUsersAsync(string searchTerm = "*", int maxResults = 100)
    {
        return await SearchUsersByFilterAsync(BuildSearchFilter(searchTerm), maxResults);
    }

    public string BuildSearchFilter(string searchTerm)
    {
        if (string.IsNullOrWhiteSpace(searchTerm) || searchTerm == "*")
        {
            return settings.UserObjectFilter;
        }

        var escaped = EscapeFilterValue(searchTerm.Trim());
        return $"(&{settings.UserObjectFilter}(|({settings.UserIdAttribute}=*{escaped}*)({settings.NameAttribute}=*{escaped}*)({settings.CommonNameAttribute}=*{escaped}*)({settings.EmailAttribute}=*{escaped}*)))";
    }

    public string BuildEmailFilter(string email)
    {
        return $"(&{settings.UserObjectFilter}({settings.EmailAttribute}={EscapeFilterValue(email.Trim())}))";
    }

    public string BuildNameFilter(string name)
    {
        var escaped = EscapeFilterValue(name.Trim());
        return $"(&{settings.UserObjectFilter}(|({settings.NameAttribute}=*{escaped}*)({settings.CommonNameAttribute}=*{escaped}*)))";
    }

    public string BuildGroupFilter(string groupIdentifier)
    {
        var escaped = EscapeFilterValue(groupIdentifier.Trim());
        return groupIdentifier.Contains('=') && groupIdentifier.Contains(',')
            ? $"(&(objectClass=group)(distinguishedName={escaped}))"
            : string.Format(System.Globalization.CultureInfo.InvariantCulture, settings.GroupSearchFilter, escaped);
    }

    public async Task<IReadOnlyList<UserRecord>> SearchUsersByFilterAsync(string filter, int maxResults = 100)
    {
        return await SearchUsersByFilterAsync(
            filter,
            ["*", "+"],
            maxResults);
    }

    public async Task<IReadOnlyList<UserRecord>> SearchUsersByFilterAsync(
        string filter,
        string[] attributes,
        int maxResults = 100)
    {
        return await SearchEntriesAsync(settings.BaseDn, filter, attributes, "sub", maxResults);
    }

    public async Task<IReadOnlyList<UserRecord>> SearchEntriesAsync(
        string baseDn,
        string filter,
        string[] attributes,
        string scope,
        int maxResults = 100)
    {
        var ldapScope = scope.ToLowerInvariant() switch
        {
            "base" => LdapConnection.ScopeBase,
            "one" => LdapConnection.ScopeOne,
            "sub" => LdapConnection.ScopeSub,
            _ => throw new ArgumentException("Search scope must be base, one, or sub.", nameof(scope))
        };

        if (maxResults < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(maxResults), "Maximum results must be positive.");
        }

        using var connection = await ConnectAndBindAsync(settings.BindDn, bindPassword);
        var results = await connection.SearchAsync(
            baseDn,
            ldapScope,
            filter,
            attributes,
            false,
            CreateSearchConstraints());

        var entries = await ReadEntriesAsync(results, maxResults);
        var users = new List<UserRecord>(entries.Count);
        foreach (var entry in entries)
        {
            users.Add(MapUserRecord(entry));
        }

        return users;
    }

    public async Task<IReadOnlyList<UserRecord>> SearchEntriesPagedAsync(
        string baseDn,
        string filter,
        string[] attributes,
        int maxResults = int.MaxValue,
        CancellationToken cancellationToken = default)
    {
        if (maxResults < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(maxResults), "Maximum results must be positive.");
        }

        using var connection = await ConnectAndBindAsync(settings.BindDn, bindPassword);
        var options = new SearchOptions(
            baseDn,
            LdapConnection.ScopeSub,
            filter,
            attributes,
            false,
            CreateSearchConstraints());
        List<LdapEntry> entries;
        try
        {
            entries = await new SimplePagedResultsControlHandler(connection)
                .SearchWithSimplePagingAsync(options, 500, cancellationToken);
        }
        catch (LdapReferralException exception) when (IsApplicationPartitionReferral(exception))
        {
            Console.Error.WriteLine(
                $"Paged search encountered an Active Directory application-partition referral; retrying with referral-aware search: {string.Join(", ", exception.GetReferrals())}");
            var results = await connection.SearchAsync(
                baseDn,
                LdapConnection.ScopeSub,
                filter,
                attributes,
                false,
                CreateSearchConstraints());
            entries = await ReadEntriesAsync(results, maxResults);
        }

        return entries
            .Take(maxResults)
            .Select(MapUserRecord)
            .ToArray();
    }

    public static bool IsValidAttributeName(string attributeName)
    {
        return attributeName.Length > 0 &&
               attributeName.All(character =>
                   char.IsAsciiLetterOrDigit(character) ||
                   character is '-' or ';' or '.');
    }

    public async Task<GroupMembershipResult> FindGroupMembersAsync(string groupIdentifier, int maxResults = 100)
    {
        var groupFilter = BuildGroupFilter(groupIdentifier);

        using var connection = await ConnectAndBindAsync(settings.BindDn, bindPassword);
        var groups = await connection.SearchAsync(
            settings.BaseDn,
            LdapConnection.ScopeSub,
            groupFilter,
            ["distinguishedName", "cn"],
            false,
            CreateSearchConstraints());

        var groupEntries = await ReadEntriesAsync(groups, 1);
        var groupDn = groupEntries.Count == 0 ? null : groupEntries[0].Dn;

        if (groupDn is null)
        {
            return new GroupMembershipResult(null, string.Empty, []);
        }

        var filter = string.Format(
            System.Globalization.CultureInfo.InvariantCulture,
            settings.GroupMemberSearchFilter,
            EscapeFilterValue(groupDn));
        var results = await connection.SearchAsync(
            settings.BaseDn,
            LdapConnection.ScopeSub,
            filter,
            ["*", "+"],
            false,
            CreateSearchConstraints());

        var entries = await ReadEntriesAsync(results, maxResults);
        var users = new List<UserRecord>(entries.Count);
        foreach (var entry in entries)
        {
            users.Add(MapUserRecord(entry));
        }

        return new GroupMembershipResult(groupDn, filter, users);
    }

    public string BuildUserFilter(string identifier)
    {
        var escaped = EscapeFilterValue(identifier.Trim());
        return identifier.Contains('=') && identifier.Contains(',')
            ? $"(&{settings.UserObjectFilter}(distinguishedName={escaped}))"
            : string.Format(
                System.Globalization.CultureInfo.InvariantCulture,
                settings.UserSearchFilter,
                escaped);
    }

    public string BuildUserIdentifierFilter(string identifier)
    {
        var escaped = EscapeFilterValue(identifier.Trim());
        if (identifier.Contains('=') && identifier.Contains(','))
        {
            return $"(&{settings.UserObjectFilter}(distinguishedName={escaped}))";
        }

        return $"(&{settings.UserObjectFilter}(|({settings.UserIdAttribute}={escaped})({settings.EmailAttribute}={escaped})({settings.NameAttribute}={escaped})))";
    }

    public async Task<UserRecord?> GetUserAsync(string identifier)
    {
        if (string.IsNullOrWhiteSpace(identifier))
        {
            return null;
        }

        var filter = BuildUserFilter(identifier);

        using var connection = await ConnectAndBindAsync(settings.BindDn, bindPassword);
        var results = await connection.SearchAsync(
            settings.BaseDn,
            LdapConnection.ScopeSub,
            filter,
            ["*", "+"],
            false,
            CreateSearchConstraints());

        var entries = await ReadEntriesAsync(results, 1);
        return entries.Count == 0 ? null : MapUserRecord(entries[0]);
    }

    public async Task<bool> ValidateCredentialsAsync(string identifier, string password)
    {
        if (string.IsNullOrWhiteSpace(identifier) || string.IsNullOrEmpty(password))
        {
            return false;
        }

        var user = await GetUserAsync(identifier);
        if (user is null || string.IsNullOrWhiteSpace(user.DistinguishedName))
        {
            return false;
        }

        try
        {
            using var connection = await ConnectAndBindAsync(user.DistinguishedName, password);
            return true;
        }
        catch (LdapException)
        {
            return false;
        }
    }

    private async Task<LdapConnection> ConnectAndBindAsync(string bindDn, string password)
    {
        var connection = new LdapConnection
        {
            SecureSocketLayer = settings.UseSslForConnection
        };

        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(8));
            await connection.ConnectAsync(settings.ConnectionHost, settings.Port, timeout.Token);
            await connection.BindAsync(bindDn, password, timeout.Token);
            return connection;
        }
        catch (Exception exception)
        {
            connection.Dispose();
            var endpointStatus = await ProbeEndpointAsync();
            var ldapDetail = exception is LdapException ldapException
                ? $" LDAP result: {ldapException.ResultCode}; diagnostic: {ldapException.LdapErrorMessage}; matched DN: {ldapException.MatchedDn}"
                : string.Empty;
            throw new InvalidOperationException(
                $"LDAP connect/bind failed for {settings.ConnectionHost}:{settings.Port} " +
                $"(LDAPS: {settings.UseSslForConnection}). {endpointStatus} " +
                $"Library error: {exception.Message}.{ldapDetail}",
                exception);
        }
    }

    private LdapSearchConstraints CreateSearchConstraints()
    {
        return new LdapSearchConstraints
        {
            ReferralFollowing = false,
            HopLimit = 5
        };
    }

    private static async Task<List<LdapEntry>> ReadEntriesAsync(ILdapSearchResults results, int maxResults)
    {
        var entries = new List<LdapEntry>();
        await using var enumerator = results.GetAsyncEnumerator();
        while (entries.Count < maxResults)
        {
            bool hasEntry;
            try
            {
                hasEntry = await enumerator.MoveNextAsync();
            }
            catch (LdapReferralException exception) when (IsApplicationPartitionReferral(exception))
            {
                Console.Error.WriteLine(
                    $"Skipping Active Directory application-partition referral: {string.Join(", ", exception.GetReferrals())}");
                continue;
            }

            if (!hasEntry)
            {
                break;
            }

            entries.Add(enumerator.Current);
        }

        return entries;
    }

    private static bool IsApplicationPartitionReferral(LdapReferralException exception)
    {
        var referrals = exception.GetReferrals();
        return referrals.Length > 0 && referrals.All(referral =>
        {
            if (!Uri.TryCreate(referral, UriKind.Absolute, out var uri))
            {
                return false;
            }

            var referredDn = Uri.UnescapeDataString(uri.AbsolutePath.TrimStart('/'));
            return referredDn.StartsWith("DC=ForestDnsZones,", StringComparison.OrdinalIgnoreCase) ||
                   referredDn.StartsWith("DC=DomainDnsZones,", StringComparison.OrdinalIgnoreCase);
        });
    }

    private async Task<string> ProbeEndpointAsync()
    {
        try
        {
            var addresses = await Dns.GetHostAddressesAsync(settings.ConnectionHost);
            if (addresses.Length == 0)
            {
                return "DNS resolved no addresses.";
            }

            using var tcp = new TcpClient();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            await tcp.ConnectAsync(settings.ConnectionHost, settings.Port, timeout.Token);
            return $"TCP probe succeeded ({string.Join(", ", addresses.Select(address => address.ToString()))}).";
        }
        catch (Exception exception) when (exception is SocketException or OperationCanceledException)
        {
            return $"DNS/TCP probe failed: {exception.Message}.";
        }
    }

    private UserRecord MapUserRecord(LdapEntry entry)
    {
        var properties = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
        var attributes = entry.GetAttributeSet();

        foreach (LdapAttribute attribute in attributes)
        {
            properties[attribute.Name] = attribute.StringValueArray;
        }

        return new UserRecord
        {
            DistinguishedName = entry.Dn,
            UserId = GetFirstValue(properties, settings.UserIdAttribute),
            SamAccountName = GetFirstValue(properties, "sAMAccountName"),
            UserPrincipalName = GetFirstValue(properties, "userPrincipalName"),
            DisplayName = GetFirstValue(properties, settings.NameAttribute),
            Mail = GetFirstValue(properties, settings.EmailAttribute),
            Department = GetFirstValue(properties, "department"),
            Title = GetFirstValue(properties, "title"),
            Manager = GetFirstValue(properties, "manager"),
            Attributes = properties
        };
    }

    private static string? GetFirstValue(IReadOnlyDictionary<string, string[]> properties, string propertyName)
    {
        return properties.TryGetValue(propertyName, out var values) && values.Length > 0
            ? values[0]
            : null;
    }

    private static string EscapeFilterValue(string input)
    {
        var builder = new StringBuilder();
        foreach (var c in input)
        {
            builder.Append(c switch
            {
                '*' => "\\2a",
                '(' => "\\28",
                ')' => "\\29",
                '\\' => "\\5c",
                '\0' => "\\00",
                _ => c.ToString()
            });
        }

        return builder.ToString();
    }
}

public sealed record GroupMembershipResult(
    string? GroupDistinguishedName,
    string MembershipFilter,
    IReadOnlyList<UserRecord> Users);

public sealed class UserRecord
{
    public string? DistinguishedName { get; set; }
    public string? UserId { get; set; }
    public string? SamAccountName { get; set; }
    public string? UserPrincipalName { get; set; }
    public string? DisplayName { get; set; }
    public string? Mail { get; set; }
    public string? Department { get; set; }
    public string? Title { get; set; }
    public string? Manager { get; set; }
    public Dictionary<string, string[]> Attributes { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}
