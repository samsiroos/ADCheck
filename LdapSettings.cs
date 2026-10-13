using System.Text.Json;

namespace ADChecker;

public sealed class LdapSettings
{
    public bool Enabled { get; init; } = true;
    public string EmailDomain { get; init; } = string.Empty;
    public string Host { get; init; } = string.Empty;
    public int Port { get; init; } = 389;
    public bool UseSsl { get; init; }
    public bool FollowReferrals { get; init; }
    public string BaseDn { get; init; } = string.Empty;
    public string BindDn { get; init; } = string.Empty;
    public string? BindPassword { get; init; }
    public string UserObjectFilter { get; init; } = "(&(objectClass=user)(objectCategory=person))";
    public string UserIdAttribute { get; init; } = "sAMAccountName";
    public string EmailAttribute { get; init; } = "mail";
    public string NameAttribute { get; init; } = "displayName";
    public string CommonNameAttribute { get; init; } = "cn";
    public string UserSearchFilter { get; init; } = string.Empty;
    public string GroupSearchFilter { get; init; } = "(&(objectClass=group)(cn={0}))";
    public string GroupMemberSearchFilter { get; init; } = "(&(objectClass=user)(objectCategory=person)(memberOf={0}))";

    public string ConnectionHost
    {
        get
        {
            if (Uri.TryCreate(Host, UriKind.Absolute, out var uri) &&
                (uri.Scheme.Equals("ldap", StringComparison.OrdinalIgnoreCase) ||
                 uri.Scheme.Equals("ldaps", StringComparison.OrdinalIgnoreCase)))
            {
                return uri.Host;
            }

            return Host;
        }
    }

    public bool UseSslForConnection =>
        UseSsl || (Uri.TryCreate(Host, UriKind.Absolute, out var uri) &&
                   uri.Scheme.Equals("ldaps", StringComparison.OrdinalIgnoreCase));

    public static (LdapSettings Settings, string BindPassword) Load(string? configPath)
    {
        var configuredPath = configPath ?? Environment.GetEnvironmentVariable("AD_CONFIG_PATH");
        var path = configuredPath ?? "config/ldap.json";
        var fileLdap = new LdapSettings();

        if (File.Exists(path))
        {
            var json = File.ReadAllText(path);
            var fileSettings = JsonSerializer.Deserialize<LdapConfigFile>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            }) ?? throw new InvalidDataException($"LDAP config file '{path}' is empty or invalid.");
            fileLdap = fileSettings.Ldap
                ?? throw new InvalidDataException($"LDAP config file '{path}' must contain an Ldap object.");
        }
        else if (configuredPath is not null)
        {
            throw new FileNotFoundException($"LDAP config file not found at '{path}'.", path);
        }

        var userIdAttribute = GetValue("AD_USER_ID_ATTRIBUTE", fileLdap.UserIdAttribute);
        var userSearchFilter = Environment.GetEnvironmentVariable("AD_USER_SEARCH_FILTER")
            ?? (string.IsNullOrWhiteSpace(fileLdap.UserSearchFilter)
                ? $"({userIdAttribute}={{0}})"
                : fileLdap.UserSearchFilter);

        var settings = new LdapSettings
        {
            Enabled = GetBool("AD_LDAP_ENABLED", fileLdap.Enabled),
            EmailDomain = GetValue("AD_EMAIL_DOMAIN", fileLdap.EmailDomain),
            Host = GetValue("AD_SERVER", fileLdap.Host),
            Port = GetInt("AD_PORT", fileLdap.Port),
            UseSsl = GetBool("AD_USE_SSL", fileLdap.UseSsl),
            BaseDn = GetValue("AD_BASE_DN", fileLdap.BaseDn),
            BindDn = GetValue("AD_BIND_DN", fileLdap.BindDn),
            BindPassword = Environment.GetEnvironmentVariable("AD_BIND_PASSWORD") ?? fileLdap.BindPassword,
            UserObjectFilter = GetValue("AD_USER_OBJECT_FILTER", fileLdap.UserObjectFilter),
            UserIdAttribute = userIdAttribute,
            EmailAttribute = GetValue("AD_EMAIL_ATTRIBUTE", fileLdap.EmailAttribute),
            NameAttribute = GetValue("AD_NAME_ATTRIBUTE", fileLdap.NameAttribute),
            CommonNameAttribute = GetValue("AD_COMMON_NAME_ATTRIBUTE", fileLdap.CommonNameAttribute),
            UserSearchFilter = userSearchFilter,
            GroupSearchFilter = GetValue("AD_GROUP_SEARCH_FILTER", fileLdap.GroupSearchFilter),
            GroupMemberSearchFilter = GetValue("AD_GROUP_MEMBER_SEARCH_FILTER", fileLdap.GroupMemberSearchFilter)
        };

        if (!settings.Enabled)
        {
            throw new InvalidOperationException("LDAP is disabled in the configuration.");
        }

        if (string.IsNullOrWhiteSpace(settings.Host) ||
            string.IsNullOrWhiteSpace(settings.BaseDn) ||
            string.IsNullOrWhiteSpace(settings.BindDn))
        {
            throw new InvalidDataException("LDAP Host, BaseDn, and BindDn must be configured.");
        }

        if (settings.Port is < 1 or > 65535)
        {
            throw new InvalidDataException("LDAP Port must be between 1 and 65535.");
        }

        foreach (var attribute in new[]
                 {
                     settings.UserIdAttribute,
                     settings.EmailAttribute,
                     settings.NameAttribute,
                     settings.CommonNameAttribute
                 })
        {
            if (!ActiveDirectoryClient.IsValidAttributeName(attribute))
            {
                throw new InvalidDataException($"Invalid configured LDAP attribute name: '{attribute}'.");
            }
        }

        ValidateFilterTemplate(settings.UserSearchFilter, "UserSearchFilter");
        ValidateFilterTemplate(settings.GroupSearchFilter, "GroupSearchFilter");
        ValidateFilterTemplate(settings.GroupMemberSearchFilter, "GroupMemberSearchFilter");
        ValidateFilter(settings.UserObjectFilter, "UserObjectFilter");

        var bindPassword = settings.BindPassword;
        if (string.IsNullOrEmpty(bindPassword))
        {
            throw new InvalidDataException("Set AD_BIND_PASSWORD in the host environment or .env file.");
        }

        return (settings, bindPassword);
    }

    private static void ValidateFilterTemplate(string filter, string settingName)
    {
        ValidateFilter(filter, settingName);
        if (!filter.Contains("{0}", StringComparison.Ordinal) ||
            filter.Count(character => character == '{') != 1 ||
            filter.Count(character => character == '}') != 1)
        {
            throw new InvalidDataException($"LDAP {settingName} must contain exactly one {{0}} placeholder.");
        }
    }

    private static void ValidateFilter(string filter, string settingName)
    {
        if (string.IsNullOrWhiteSpace(filter) || !filter.StartsWith('(') || !filter.EndsWith(')'))
        {
            throw new InvalidDataException($"LDAP {settingName} must be a valid parenthesized LDAP filter.");
        }
    }

    private static string GetValue(string name, string fallback)
    {
        return Environment.GetEnvironmentVariable(name) ?? fallback;
    }

    private static bool GetBool(string name, bool fallback)
    {
        var value = Environment.GetEnvironmentVariable(name);
        return value is null ? fallback : bool.Parse(value);
    }

    private static int GetInt(string name, int fallback)
    {
        var value = Environment.GetEnvironmentVariable(name);
        return value is null ? fallback : int.Parse(value, System.Globalization.CultureInfo.InvariantCulture);
    }

    private sealed class LdapConfigFile
    {
        public LdapSettings? Ldap { get; init; }
    }
}
