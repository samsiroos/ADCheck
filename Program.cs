using System.Text.Json;
using System.Text;
using System.Globalization;

namespace ADChecker;

public static class Program
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    public static async Task<int> Main(string[] args)
    {
        if (args.Length > 0 && (args.Contains("--help", StringComparer.OrdinalIgnoreCase) || args.Contains("-h", StringComparer.OrdinalIgnoreCase)))
        {
            PrintUsage();
            return 0;
        }

        LdapSettings? settings = null;
        var command = args.Length == 0 ? "menu" : args[0].TrimStart('-').ToLowerInvariant();
        try
        {
            var options = ParseOptions(args);
            var loaded = LdapSettings.Load(options.ConfigPath);
            settings = loaded.Settings;
            var client = new ActiveDirectoryClient(loaded.Settings, loaded.BindPassword);

            if (args.Length == 0 || command == "menu")
            {
                return await RunMenuAsync(client, settings);
            }

            return command switch
            {
                "connect" => await HandleConnectAsync(client, settings),
                "search" => await HandleSearchAsync(client, settings, options),
                "user" => await HandleUserAsync(client, settings, options),
                "validate" => await HandleValidateAsync(client, settings, options),
                "host" => await RunContainerHostAsync(),
                _ => ThrowUsage($"Unknown command: {args[0]}")
            };
        }
        catch (Exception ex)
        {
            if (settings is not null && command is not "host" and not "menu")
            {
                WriteLdapError(ex, settings);
            }
            else
            {
                Console.Error.WriteLine($"Error: {ex.Message}");
                if (ex.InnerException is not null)
                {
                    Console.Error.WriteLine($"Details: {ex.InnerException.Message}");
                }
            }

            return 1;
        }
    }

    private static async Task<int> HandleConnectAsync(ActiveDirectoryClient client, LdapSettings settings)
    {
        await client.TestConnectionAsync();
        Console.WriteLine("Connected successfully to Active Directory.");
        PrintLdapQuery("(objectClass=*)", settings, "objectClass");
        return 0;
    }

    private static async Task<int> HandleSearchAsync(ActiveDirectoryClient client, LdapSettings settings, CommandOptions options)
    {
        var filter = client.BuildSearchFilter(options.SearchTerm ?? "*");
        var users = await client.SearchUsersByFilterAsync(filter, options.Limit);
        await ShowSearchResultsAsync(client, settings, users, filter);
        return 0;
    }

    private static async Task<int> HandleUserAsync(ActiveDirectoryClient client, LdapSettings settings, CommandOptions options)
    {
        var identifier = options.Identifier ?? throw new ArgumentException("Provide --identifier or --user.");
        var filter = client.BuildUserFilter(identifier);
        var user = await client.GetUserAsync(identifier);

        if (user is null)
        {
            Console.WriteLine("User not found.");
            PrintLdapQuery(filter, settings);
            return 1;
        }

        Console.WriteLine(JsonSerializer.Serialize(user, JsonOptions));
        PrintLdapQuery(filter, settings);
        return 0;
    }

    private static async Task<int> HandleValidateAsync(ActiveDirectoryClient client, LdapSettings settings, CommandOptions options)
    {
        var identifier = options.Identifier ?? throw new ArgumentException("Provide --identifier or --user.");
        var password = options.TargetPassword;
        if (string.IsNullOrEmpty(password))
        {
            password = Environment.GetEnvironmentVariable("AD_TARGET_PASSWORD");
        }

        if (string.IsNullOrEmpty(password))
        {
            throw new ArgumentException("Provide --target-password or set AD_TARGET_PASSWORD.");
        }

        var isValid = await client.ValidateCredentialsAsync(identifier, password);
        Console.WriteLine(isValid ? "Password is valid." : "Password is invalid or account not found.");
        Console.WriteLine("Password validation is an LDAP bind; it does not have a search filter.");
        PrintLdapQuery(client.BuildUserFilter(identifier), settings, "distinguishedName");
        return isValid ? 0 : 1;
    }

    private static async Task<int> RunMenuAsync(ActiveDirectoryClient client, LdapSettings settings)
    {
        while (true)
        {
            Console.WriteLine();
            Console.WriteLine("ADChecker - Active Directory");
            Console.WriteLine($"  1 - Find user by identifier ({settings.UserIdAttribute})");
            Console.WriteLine("  2 - Find user by email");
            Console.WriteLine("  3 - Search users by name");
            Console.WriteLine("  4 - Find users who are direct members of a group");
            Console.WriteLine("  5 - Check a user's password");
            Console.WriteLine("  6 - Get a custom attribute for a user");
            Console.WriteLine("  7 - Run a manual LDAP search");
            Console.WriteLine("  8 - List all attributes for a user");
            Console.WriteLine("  9 - Export users with a selected attribute to CSV");
            Console.WriteLine("  0 - Exit");
            Console.Write("Select: ");

            var choice = Console.ReadLine()?.Trim();
            if (choice is "0" or null)
            {
                return 0;
            }

            try
            {
                switch (choice)
                {
                    case "1":
                        await RunUserSearchAsync(client, settings, $"User identifier ({settings.UserIdAttribute} or DN): ",
                            input => client.BuildUserFilter(input));
                        break;
                    case "2":
                        await RunUserSearchAsync(client, settings, "Email address: ",
                            client.BuildEmailFilter);
                        break;
                    case "3":
                        await RunUserSearchAsync(client, settings, "Name (partial match): ",
                            client.BuildNameFilter);
                        break;
                    case "4":
                        await RunGroupMembersAsync(client, settings);
                        break;
                    case "5":
                        await ValidateFromMenuAsync(client, settings);
                        break;
                    case "6":
                        await GetCustomAttributeAsync(client, settings);
                        break;
                    case "7":
                        await RunManualLdapSearchAsync(client, settings);
                        break;
                    case "8":
                        await ListUserAttributesAsync(client, settings);
                        break;
                    case "9":
                        await ExportUsersByAttributeAsync(client, settings);
                        break;
                    default:
                        Console.WriteLine("Choose one of the listed options.");
                        break;
                }
            }
            catch (Exception ex)
            {
                if (ex is IOException or UnauthorizedAccessException)
                {
                    Console.Error.WriteLine($"File operation failed: {ex.Message}");
                }
                else
                {
                    WriteLdapError(ex, settings);
                }
            }
        }
    }

    private static async Task RunUserSearchAsync(
        ActiveDirectoryClient client,
        LdapSettings settings,
        string prompt,
        Func<string, string> filterFactory)
    {
        var input = ReadRequired(prompt);
        var filter = filterFactory(input);
        var users = await client.SearchUsersByFilterAsync(filter);
        await ShowSearchResultsAsync(client, settings, users, filter);
    }

    private static async Task RunGroupMembersAsync(ActiveDirectoryClient client, LdapSettings settings)
    {
        var group = ReadRequired("Group CN or distinguished name: ");
        var groupFilter = group.Contains('=') && group.Contains(',')
            ? $"(&(objectClass=group)(distinguishedName={EscapeFilterValue(group)}))"
            : $"(&(objectClass=group)(|(cn={EscapeFilterValue(group)})(name={EscapeFilterValue(group)})))";

        var membership = await client.FindGroupMembersAsync(group);
        Console.WriteLine("Direct group membership only (nested groups are not expanded).");
        if (membership.GroupDistinguishedName is null)
        {
            Console.WriteLine("Group not found.");
            PrintLdapQuery(groupFilter, settings);
            return;
        }

        await ShowSearchResultsAsync(client, settings, membership.Users, membership.MembershipFilter);
    }

    private static async Task ShowSearchResultsAsync(
        ActiveDirectoryClient client,
        LdapSettings settings,
        IReadOnlyList<UserRecord> users,
        string queryFilter)
    {
        if (users.Count == 0)
        {
            Console.WriteLine("No users found.");
            PrintLdapQuery(queryFilter, settings);
            return;
        }

        for (var displayIndex = 0; displayIndex < users.Count; displayIndex++)
        {
            Console.WriteLine();
            Console.WriteLine($"===== User {displayIndex + 1} of {users.Count} =====");
            Console.WriteLine(JsonSerializer.Serialize(users[displayIndex], JsonOptions));
            PrintLdapQuery(queryFilter, settings);
        }

        Console.WriteLine();
        Console.Write("Select a user number to fetch the latest attributes and optionally check its password (Enter to return): ");
        var selection = Console.ReadLine()?.Trim();
        if (!int.TryParse(selection, out var index) || index < 1 || index > users.Count)
        {
            return;
        }

        var selected = users[index - 1];
        var key = selected.UserId ?? selected.SamAccountName ?? selected.DistinguishedName;
        if (string.IsNullOrWhiteSpace(key))
        {
            Console.WriteLine("Selected result has no account name or distinguished name.");
            return;
        }

        var detailFilter = client.BuildUserFilter(key);
        var fullUser = await client.GetUserAsync(key);
        if (fullUser is null)
        {
            Console.WriteLine("User details were not found.");
            PrintLdapQuery(detailFilter, settings);
            return;
        }

        Console.WriteLine();
        Console.WriteLine(JsonSerializer.Serialize(fullUser, JsonOptions));
        PrintLdapQuery(detailFilter, settings);
        Console.Write("Check this user's password? (y/N): ");
        if (Console.ReadLine()?.Trim().Equals("y", StringComparison.OrdinalIgnoreCase) == true)
        {
            var password = ReadSecret("User password: ");
            var valid = await client.ValidateCredentialsAsync(key, password);
            Console.WriteLine(valid ? "Password is valid." : "Password is invalid or account not found.");
        }
    }

    private static async Task GetCustomAttributeAsync(ActiveDirectoryClient client, LdapSettings settings)
    {
        var identifier = ReadRequired($"User identifier ({settings.UserIdAttribute}, email, or DN): ");
        var attributeName = ReadRequired("LDAP attribute name (for example: employeeNumber): ");
        if (!ActiveDirectoryClient.IsValidAttributeName(attributeName))
        {
            throw new ArgumentException("Invalid LDAP attribute name. Use letters, digits, '.', ';', or '-'.");
        }

        var filter = client.BuildUserIdentifierFilter(identifier);
        var users = await client.SearchUsersByFilterAsync(filter, [attributeName], 1);

        if (users.Count == 0)
        {
            Console.WriteLine("User not found.");
        }
        else if (!users[0].Attributes.TryGetValue(attributeName, out var values))
        {
            Console.WriteLine($"Attribute '{attributeName}' is not present or is not readable for this user.");
        }
        else
        {
            Console.WriteLine($"User: {users[0].UserId ?? users[0].SamAccountName ?? users[0].DistinguishedName}");
            Console.WriteLine($"{attributeName}: {JsonSerializer.Serialize(values, JsonOptions)}");
        }

        PrintLdapQuery(filter, settings, attributeName);
    }

    private static async Task ListUserAttributesAsync(ActiveDirectoryClient client, LdapSettings settings)
    {
        var identifier = ReadRequired("User identifier (UserId, email, or DN): ");
        var filter = client.BuildUserIdentifierFilter(identifier);
        var users = await client.SearchUsersByFilterAsync(filter, ["*", "+"], 1);

        if (users.Count == 0)
        {
            Console.WriteLine("User not found.");
            PrintLdapQuery(filter, settings);
            return;
        }

        var user = users[0];
        Console.WriteLine($"User: {user.UserId ?? user.DistinguishedName}");
        Console.WriteLine($"Configured UserId attribute: {settings.UserIdAttribute}");
        foreach (var (attributeName, values) in user.Attributes.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase))
        {
            Console.WriteLine($"{attributeName}: {string.Join(" | ", values)}");
        }

        PrintLdapQuery(filter, settings);
    }

    private static async Task ExportUsersByAttributeAsync(ActiveDirectoryClient client, LdapSettings settings)
    {
        var attributeName = ReadRequired("LDAP attribute to export (for example: employeeNumber): ");
        if (!ActiveDirectoryClient.IsValidAttributeName(attributeName))
        {
            throw new ArgumentException("Invalid LDAP attribute name. Use letters, digits, '.', ';', or '-'.");
        }

        Console.Write("Maximum users to export (blank for all): ");
        var limitInput = Console.ReadLine()?.Trim();
        var limit = string.IsNullOrEmpty(limitInput)
            ? int.MaxValue
            : int.TryParse(limitInput, NumberStyles.None, CultureInfo.InvariantCulture, out var parsedLimit) && parsedLimit > 0
                ? parsedLimit
                : throw new ArgumentException("Maximum users must be a positive integer.");

        Console.Write($"CSV output path (default /output/users-{attributeName}.csv): ");
        var outputPath = Console.ReadLine()?.Trim();
        if (string.IsNullOrWhiteSpace(outputPath))
        {
            outputPath = $"/output/users-{attributeName}.csv";
        }

        var exportRoot = Path.GetFullPath("/output");
        var fullOutputPath = Path.GetFullPath(Path.IsPathRooted(outputPath)
            ? outputPath
            : Path.Combine(exportRoot, outputPath));
        if (!fullOutputPath.StartsWith(exportRoot + Path.DirectorySeparatorChar, StringComparison.Ordinal))
        {
            throw new ArgumentException("Export path must be inside /output, which is bind-mounted to the configured host directory.");
        }

        var exportAttributes = new[]
        {
            settings.UserIdAttribute,
            settings.NameAttribute,
            settings.EmailAttribute,
            attributeName
        }.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var filter = settings.UserObjectFilter;
        var users = await client.SearchEntriesPagedAsync(settings.BaseDn, filter, exportAttributes, limit);

        Directory.CreateDirectory(Path.GetDirectoryName(fullOutputPath)!);
        await using (var writer = new StreamWriter(fullOutputPath, false, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true)))
        {
            var headers = new[]
            {
                settings.UserIdAttribute,
                settings.NameAttribute,
                settings.EmailAttribute,
                "distinguishedName",
                attributeName
            };
            await writer.WriteLineAsync(string.Join(',', headers.Select(EscapeCsv)));

            foreach (var user in users)
            {
                var fields = new[]
                {
                    GetAttribute(user, settings.UserIdAttribute),
                    GetAttribute(user, settings.NameAttribute),
                    GetAttribute(user, settings.EmailAttribute),
                    user.DistinguishedName ?? string.Empty,
                    GetAttribute(user, attributeName)
                };
                await writer.WriteLineAsync(string.Join(',', fields.Select(EscapeCsv)));
            }
        }

        Console.WriteLine($"Exported {users.Count} user(s); column '{attributeName}' is empty where that attribute is absent.");
        PrintLdapQuery(filter, settings, string.Join(',', exportAttributes));
        Console.WriteLine($"CSV saved to {fullOutputPath} inside the container; the host bind mount defaults to /etc/app/ADchecker/exports.");
    }

    private static string GetAttribute(UserRecord user, string attributeName)
    {
        return user.Attributes.TryGetValue(attributeName, out var values)
            ? string.Join("; ", values)
            : string.Empty;
    }

    private static string EscapeCsv(string value)
    {
        return $"\"{value.Replace("\"", "\"\"", StringComparison.Ordinal)}\"";
    }

    private static async Task RunManualLdapSearchAsync(ActiveDirectoryClient client, LdapSettings settings)
    {
        Console.Write($"Base DN (Enter for {settings.BaseDn}): ");
        var baseDn = Console.ReadLine()?.Trim();
        if (string.IsNullOrWhiteSpace(baseDn))
        {
            baseDn = settings.BaseDn;
        }

        var filter = ReadRequired("LDAP filter (for example: (employeeID=12345)): ");
        Console.Write("Attributes, comma/space separated (Enter for * +): ");
        var attributeInput = Console.ReadLine()?.Trim();
        var attributes = string.IsNullOrWhiteSpace(attributeInput)
            ? ["*", "+"]
            : attributeInput.Split([',', ' ', '\t'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        if (attributes.Any(attribute =>
                attribute != "*" &&
                attribute != "+" &&
                !ActiveDirectoryClient.IsValidAttributeName(attribute)))
        {
            throw new ArgumentException("Attribute names may contain letters, digits, '.', ';', or '-'. Use * or + for all attributes.");
        }

        Console.Write("Scope (base/one/sub; default sub): ");
        var scope = Console.ReadLine()?.Trim().ToLowerInvariant();
        if (string.IsNullOrEmpty(scope))
        {
            scope = "sub";
        }
        if (scope is not ("base" or "one" or "sub"))
        {
            throw new ArgumentException("Scope must be base, one, or sub.");
        }

        Console.Write("Maximum results (default 100): ");
        var limitInput = Console.ReadLine()?.Trim();
        var limit = string.IsNullOrEmpty(limitInput)
            ? 100
            : int.TryParse(limitInput, out var parsedLimit) && parsedLimit > 0
                ? parsedLimit
                : throw new ArgumentException("Maximum results must be a positive integer.");

        var users = await client.SearchEntriesAsync(baseDn, filter, attributes, scope, limit);
        if (users.Count == 0)
        {
            Console.WriteLine("No entries found.");
            PrintLdapQuery(filter, settings, string.Join(',', attributes), baseDn, scope);
            return;
        }

        for (var index = 0; index < users.Count; index++)
        {
            Console.WriteLine();
            Console.WriteLine($"===== Entry {index + 1} of {users.Count} =====");
            Console.WriteLine(JsonSerializer.Serialize(users[index], JsonOptions));
            PrintLdapQuery(filter, settings, string.Join(',', attributes), baseDn, scope);
        }
    }

    private static async Task ValidateFromMenuAsync(ActiveDirectoryClient client, LdapSettings settings)
    {
        var identifier = ReadRequired($"User identifier ({settings.UserIdAttribute} or DN): ");
        var password = ReadSecret("User password: ");
        var valid = await client.ValidateCredentialsAsync(identifier, password);
        Console.WriteLine(valid ? "Password is valid." : "Password is invalid or account not found.");
        Console.WriteLine("Password validation uses an LDAP bind as the selected user (not an LDAP search query).");
        PrintLdapQuery(client.BuildUserFilter(identifier), settings);
    }

    private static string ReadRequired(string prompt)
    {
        Console.Write(prompt);
        var value = Console.ReadLine()?.Trim();
        return string.IsNullOrWhiteSpace(value)
            ? throw new ArgumentException("A value is required.")
            : value;
    }

    private static string ReadSecret(string prompt)
    {
        if (Console.IsInputRedirected)
        {
            return ReadRequired(prompt);
        }

        Console.Write(prompt);
        var secret = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                return secret.ToString();
            }

            if (key.Key == ConsoleKey.Backspace)
            {
                if (secret.Length > 0)
                {
                    secret.Length--;
                }
                continue;
            }

            if (!char.IsControl(key.KeyChar))
            {
                secret.Append(key.KeyChar);
            }
        }
    }

    private static async Task<int> RunContainerHostAsync()
    {
        Console.WriteLine("ADChecker container is ready. Run `docker exec -it ADchecker ADchecker` to open the menu.");
        await Task.Delay(Timeout.InfiniteTimeSpan);
        return 0;
    }

    private static void PrintLdapQuery(
        string filter,
        LdapSettings settings,
        string attributes = "*,+",
        string? baseDn = null,
        string scope = "sub")
    {
        baseDn ??= settings.BaseDn;
        var attributeList = attributes.Split([',', ' ', '\t'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var protocol = settings.UseSslForConnection ? "ldaps" : "ldap";
        var escapedBaseDn = Uri.EscapeDataString(baseDn);
        var escapedAttributes = Uri.EscapeDataString(string.Join(',', attributeList));
        var escapedFilter = Uri.EscapeDataString(filter);
        var url = $"{protocol}://{settings.ConnectionHost}:{settings.Port}/{escapedBaseDn}?{escapedAttributes}?{scope}?{escapedFilter}";
        var readableCommand = new StringBuilder()
            .Append("ldapsearch -x -H ")
            .Append(ShellQuote($"{protocol}://{settings.ConnectionHost}:{settings.Port}"))
            .Append(" -D ")
            .Append(ShellQuote(settings.BindDn))
            .Append(" -W -b ")
            .Append(ShellQuote(baseDn))
            .Append(" -s ")
            .Append(scope)
            .Append(' ')
            .Append(ShellQuote(filter));

        foreach (var attribute in attributeList)
        {
            readableCommand.Append(' ').Append(ShellQuote(attribute));
        }

        Console.WriteLine();
        Console.WriteLine("Readable LDAP query (ldapsearch prompts for the bind password):");
        Console.WriteLine(readableCommand);
        Console.WriteLine("LDAP URL (percent-encoded by design):");
        Console.WriteLine(url);
        Console.WriteLine();
    }

    private static string ShellQuote(string value)
    {
        return $"'{value.Replace("'", "'\\''", StringComparison.Ordinal)}'";
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

    private static void WriteLdapError(Exception exception, LdapSettings settings)
    {
        Console.Error.WriteLine($"LDAP operation failed for {settings.ConnectionHost}:{settings.Port} (LDAPS: {settings.UseSslForConnection}).");
        Console.Error.WriteLine($"Error: {exception.Message}");
        for (Exception? current = exception; current is not null; current = current.InnerException)
        {
            if (current is Novell.Directory.Ldap.LdapException ldapException)
            {
                Console.Error.WriteLine(
                    $"LDAP result detail: {ldapException.ResultCode}; " +
                    $"server message: {ldapException.LdapErrorMessage ?? "(none)"}; " +
                    $"matched DN: {ldapException.MatchedDn ?? "(none)"}.");
            }

            if (current is Novell.Directory.Ldap.LdapReferralException referralException)
            {
                var referrals = referralException.GetReferrals();
                if (referrals.Length > 0)
                {
                    Console.Error.WriteLine($"Referral targets: {string.Join(", ", referrals)}");
                }
            }
        }
        if (exception.InnerException is not null)
        {
            Console.Error.WriteLine($"Details: {exception.InnerException.Message}");
        }
        Console.Error.WriteLine("AD application-partition referrals are skipped; other referrals are reported for diagnosis.");
    }

    private static int ThrowUsage(string message)
    {
        Console.Error.WriteLine(message);
        PrintUsage();
        return 1;
    }

    private static void PrintUsage()
    {
        Console.WriteLine("ADChecker - Active Directory explorer");
        Console.WriteLine();
        Console.WriteLine("Usage:");
        Console.WriteLine("  ADchecker                 Open interactive menu");
        Console.WriteLine("  ADchecker menu            Open interactive menu");
        Console.WriteLine("  ADchecker host            Run the persistent container host");
        Console.WriteLine("  ADChecker connect [--config /app/config/ldap.json]");
        Console.WriteLine("  ADChecker search [--filter john] [--limit 20]");
        Console.WriteLine("  ADChecker user --identifier jdoe");
        Console.WriteLine("  ADChecker validate --identifier jdoe [--target-password password]");
        Console.WriteLine("  CSV exports from menu option 9 default to /output/users-<attribute>.csv");
        Console.WriteLine();
        Console.WriteLine("Options:");
        Console.WriteLine("  --config           Path to the host-mounted LDAP JSON config");
        Console.WriteLine("  --filter, --search Search term (default: *)");
        Console.WriteLine("  --identifier       User login, email, CN, or DN");
        Console.WriteLine("  --target-password  Password to validate (or set AD_TARGET_PASSWORD)");
        Console.WriteLine("  --limit            Maximum search results (default: 100)");
        Console.WriteLine("  --help             Show this help");
    }

    private static CommandOptions ParseOptions(string[] args)
    {
        var options = new CommandOptions();

        for (var i = 1; i < args.Length; i++)
        {
            var arg = args[i];
            var value = GetNextValue(args, ref i);

            switch (arg)
            {
                case "--config":
                    options.ConfigPath = value;
                    break;
                case "-f":
                case "--filter":
                case "--search":
                    options.SearchTerm = value;
                    break;
                case "-i":
                case "--identifier":
                case "--user":
                    options.Identifier = value;
                    break;
                case "-l":
                case "--limit":
                    options.Limit = int.TryParse(value, out var limit) && limit > 0 ? limit : 100;
                    break;
                case "--target-password":
                    options.TargetPassword = value;
                    break;
                default:
                    throw new ArgumentException($"Unknown option: {arg}");
            }
        }

        return options;
    }

    private static string? GetNextValue(string[] args, ref int index)
    {
        if (index + 1 >= args.Length || args[index + 1].StartsWith("--", StringComparison.Ordinal))
        {
            return null;
        }

        return args[++index];
    }

    private sealed class CommandOptions
    {
        public string? ConfigPath { get; set; }
        public string? SearchTerm { get; set; }
        public string? Identifier { get; set; }
        public string? TargetPassword { get; set; }
        public int Limit { get; set; } = 100;
    }
}
