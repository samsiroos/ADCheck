# ADChecker

A small .NET console app for Active Directory LDAP operations:

- Connect to an AD domain controller
- Search users
- Return all readable user attributes
- Validate a user's password

## Host-side configuration

Docker Compose reads LDAP settings from the host-side `.env` file and passes them to the container as environment variables. The `.env` is ignored by Git and excluded from the Docker build context; do not include it in the image tar. The values supplied for this deployment are set in `.env`.

The bind password is stored only in `.env`, not in the image. Keep `.env` private. If the password already shared in chat is an active credential, rotate it. For environments that prefer JSON, the app can also read `config/ldap.json`; environment variables override JSON values.

## Build and open the interactive menu

From the deployment directory, with `.env` and `config/ldap.json` present:

```sh
docker compose -f docker-compose.prod.yml up -d
docker exec -it ADchecker ADchecker
```

The interactive menu supports user lookup by the configured user-ID attribute, email, or name; direct group membership search; a custom LDAP attribute lookup; a manual LDAP search; password validation with hidden password input; a complete attribute listing for one user; and CSV export of one chosen attribute for every user. Search results display all readable user and operational attributes (`*` and `+`) for each matching user, followed by a readable `ldapsearch` command and an LDAP URL. The URL is percent-encoded as required for URL syntax; use the `ldapsearch` form when you want to read or edit the query. The custom-attribute option asks for the user identifier and attribute name (for example `employeeNumber`), requests only that attribute, and prints the readable query and URL after the value.

Option 7 runs a manual query. Enter a base DN (or press Enter for the configured base), an LDAP filter, requested attributes (`* +` by default), scope (`base`, `one`, or `sub`), and a result limit.

Option 8 lists the selected user's attribute names and values. Option 9 exports a CSV containing the configured user ID, display name, email, DN, and the chosen attribute for every entry matched by the configured user-object filter. The query uses LDAP paging; if paging encounters an AD application-partition referral, the export retries through the referral-aware search path. The chosen-attribute column is empty when an entry has no value for it. The CSV is written under `/output` in the container, bind-mounted directly to `/etc/app/ADchecker/exports` on the host by default; no named Docker volume or `docker cp` is used. Set `AD_EXPORT_HOST_PATH` in `.env` to choose a different host directory.

Before starting the container on the server, create the host directory and allow the non-root container user (UID 1654) to write there:

```sh
mkdir -p /etc/app/ADchecker/exports
chown 1654:1654 /etc/app/ADchecker/exports
```

The Compose bind mount explicitly stays read-write even though the container root filesystem is read-only. Verify the running container has that mount enabled with:

```sh
docker inspect ADchecker --format '{{range .Mounts}}{{printf "%s -> %s (RW=%v)\n" .Source .Destination .RW}}{{end}}'
```

The exports directory must appear as `/output (RW=true)`. If it is absent or read-only, verify the Compose file being used and `AD_EXPORT_HOST_PATH` in `.env`, then recreate the container with `docker compose -f docker-compose.prod.yml up -d --force-recreate`. If the mount reports `RW=true` but writing still returns “read-only file system,” the host filesystem containing the source directory is mounted read-only.

For OpenLDAP, set schema-specific values in `.env` or `config/ldap.json`. Example for `inetOrgPerson` entries:

```env
AD_USER_ID_ATTRIBUTE=uid
AD_EMAIL_ATTRIBUTE=mail
AD_NAME_ATTRIBUTE=cn
AD_COMMON_NAME_ATTRIBUTE=cn
AD_USER_OBJECT_FILTER=(objectClass=inetOrgPerson)
AD_USER_SEARCH_FILTER=(uid={0})
```

Group searches depend on the OpenLDAP schema and membership overlay. Configure `AD_GROUP_SEARCH_FILTER` and `AD_GROUP_MEMBER_SEARCH_FILTER` to match your server; AD-style `memberOf` is not a standard OpenLDAP attribute. User prompts and output use `AD_USER_ID_ATTRIBUTE`, so deployments using `sAMAccountName` or `uid` are supported.

For example, filter `(sAMAccountName=example-user)` with attribute `employeeID` produces a readable command like:

```sh
ldapsearch -x -H 'ldap://ldap.example.com:389' -D 'cn=example-user,ou=ServiceAccounts,dc=example,dc=com' -W -b 'dc=example,dc=com' -s sub '(sAMAccountName=example-user)' employeeID
```

`ldapsearch -W` prompts for the bind password; it is not embedded in the command. Enter `0` to exit the menu. The container stays running so you can open another menu later.

When querying a domain naming context, Active Directory may also return referrals to `ForestDnsZones` or `DomainDnsZones`. Those are separate DNS/application partitions and do not contain the user results; ADChecker skips those referrals instead of trying to bind to them. Other referral targets are shown in the error output and may indicate that the configured base DN spans other domains that need to be reachable.

Run a command without the menu if needed:

```sh
docker exec ADchecker ADchecker connect
docker exec ADchecker ADchecker search --filter john --limit 20
docker exec ADchecker ADchecker user --identifier jdoe
```

`docker exec` should use `-it` for the interactive menu so prompts and hidden password entry work.

## Production deployment

The persistent idle host makes `docker exec` available. The production Compose file adds a read-only root filesystem, bounded temporary filesystem, non-root user, dropped Linux capabilities, `no-new-privileges`, CPU/memory/PID limits, and rotating local Docker logs. The root process does not initiate LDAP connections; each menu session/command performs its own connection.

```sh
docker compose -f docker-compose.prod.yml up -d
docker compose -f docker-compose.prod.yml logs
docker compose -f docker-compose.prod.yml down
```

The healthcheck is disabled because the idle host is not an LDAP connection monitor. Use the menu's connection/search operations to check AD reachability.

### Equivalent `docker run`

After loading the image, start the persistent container with equivalent hardening:

```sh
docker run --detach --name ADchecker --restart unless-stopped --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL --security-opt no-new-privileges --init \
  --pids-limit 64 --memory 256m --cpus 0.5 \
  --log-driver local --log-opt max-size=10m --log-opt max-file=3 \
  --env-file .env --volume "$(pwd)/config:/app/config:ro" \
  --volume "/etc/app/ADchecker/exports:/output" adchecker-cli:latest
```

Then open the menu using `docker exec -it ADchecker ADchecker`. Use `docker exec ADchecker ADchecker connect` or other commands for one-shot CLI operations.

## Export the image to a tar file

Build the image, then save it in Docker's portable image archive format:

```powershell
docker build --tag adchecker-cli:latest .
docker save --output ADChecker-cli.tar adchecker-cli:latest
```

Copy `ADChecker-cli.tar`, `docker-compose.prod.yml`, `.env`, and `config/ldap.json` to the deployment directory on the server. Transfer `.env` securely. Then load and start the image:

```sh
docker load --input ADChecker-cli.tar
docker compose -f docker-compose.prod.yml up -d
docker exec -it ADchecker ADchecker
```

Keep `.env` outside the tar archive; it is not part of the image. The config directory is mounted read-only from the host.

## Build and run without Docker

Requires .NET 10 SDK and network access to the domain controller:

```powershell
dotnet build
$env:AD_BIND_PASSWORD = "your-bind-account-password"
dotnet run -- connect
dotnet run -- search --filter john --limit 20
dotnet run -- user --identifier jdoe
dotnet run -- validate --identifier jdoe --target-password "user-password"
```

## LDAP settings

The app reads `AD_*` environment variables from `.env` through Docker Compose. It can also read `Ldap` settings from `config/ldap.json`; override the file path with `AD_CONFIG_PATH` or `--config`. `AD_SERVER` may be a DNS name or an `ldap://`/`ldaps://` URL; `AD_PORT` is used as configured. AD `ForestDnsZones` and `DomainDnsZones` search referrals are skipped because they are separate application partitions, not user containers; other referrals are reported so the domain/DC configuration can be corrected without forwarding bind credentials automatically. Set `AD_USE_SSL=true` (or use an `ldaps://` host) to enable LDAPS. Do not use unencrypted LDAP across untrusted networks.


## License

ADChecker is licensed under the **Apache License, Version 2.0**.

You are free to:

- Use ADChecker for personal, educational, and commercial purposes.
- Modify, fork, and redistribute the software.
- Integrate ADChecker into proprietary or closed-source applications.
- Distribute modified versions, subject to the license terms.

When redistributing ADChecker or derivative works, you must comply with the Apache License, including its applicable copyright, license, attribution, and modification-notice requirements.

Commercial use does not require separate permission from the author.

See [LICENSE](LICENSE) and [NOTICE](NOTICE) for details.

## Disclaimer and Responsible Use

**IMPORTANT: USE AT YOUR OWN RISK.**

ADChecker is provided **"AS IS"**, without warranties or conditions of any kind, to the maximum extent permitted by applicable law.

ADChecker is intended for authorized Active Directory and OpenLDAP administration, diagnostics, development, and troubleshooting.

Users are responsible for:

- Obtaining appropriate authorization before accessing directory services.
- Protecting LDAP credentials and authentication information.
- Reviewing generated queries before executing them.
- Securing CSV exports and other potentially sensitive directory data.
- Ensuring compliance with applicable laws and organizational security policies.
- Evaluating the software's suitability before using it in production environments.

The author and contributors shall not be liable for damages, data loss, security incidents, service interruptions, or other consequences arising from the use or misuse of this software, to the maximum extent permitted by applicable law.

This section supplements the warranty disclaimer and limitation of liability contained in the Apache License, Version 2.0.

## Contributions

Contributions, bug reports, and feature suggestions are welcome.

You may freely fork and modify ADChecker under the terms of the Apache License, Version 2.0.

However, changes submitted to the official repository must be reviewed and approved by the project maintainer before being merged.

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a Pull Request.

## Author and Maintainer

**Sam Siroos**

- GitHub: https://github.com/samsiroos
- Project: https://github.com/samsiroos/ADCheck
- Website: https://pwaapps.com

Copyright © 2026 Sam Siroos.
