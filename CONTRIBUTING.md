# Contributing to ADChecker

Thank you for your interest in contributing to ADChecker!

ADChecker is an open-source utility designed to simplify Active Directory and OpenLDAP diagnostics, LDAP query generation, and directory data inspection.

Contributions, bug reports, improvements, and documentation updates are welcome.

## 1. Reporting Issues

Before opening a new issue, please check whether a similar issue already exists.

When reporting a bug, include:

- A clear description of the problem.
- Steps to reproduce the issue.
- Expected and actual behavior.
- Relevant application, .NET, Docker, and LDAP server versions.
- Sanitized logs or error messages, when applicable.

**Never include real credentials, access tokens, passwords, personal directory data, or confidential infrastructure details in public issues.**

For suspected security vulnerabilities, contact the maintainer privately rather than disclosing sensitive details in a public issue.

## 2. Contributing Code

To contribute code:

1. Fork the repository.
2. Create a feature or bug-fix branch.
3. Implement and test your changes.
4. Update documentation where necessary.
5. Submit a Pull Request to the main repository.

Please keep Pull Requests focused and explain the purpose of your changes.

## 3. Review and Approval

All changes submitted to the official ADChecker repository are subject to maintainer review and approval.

The project maintainer reserves the right to accept, request modifications to, or reject any Pull Request.

Submitting a Pull Request does not guarantee that the contribution will be merged.

Independent forks and modifications are permitted under the Apache License, Version 2.0, and do not require maintainer approval.

## 4. Security and Responsible Development

Because ADChecker interacts with directory services, contributors should:

- Avoid logging or exposing credentials.
- Protect sensitive LDAP attributes and directory information.
- Avoid introducing insecure authentication defaults.
- Preserve compatibility with Active Directory and OpenLDAP where applicable.
- Consider security implications of query generation and CSV export.
- Avoid committing real organizational data or environment-specific secrets.

## 5. Testing

Before submitting changes, verify that the project builds successfully and that affected CLI functionality behaves as expected.

Where relevant, test Docker builds and LDAP operations using authorized test environments.

## 6. Licensing

By submitting a contribution, you agree that your contribution is made available under the Apache License, Version 2.0, and that you have the necessary rights to submit it.

Contributors retain their applicable copyrights.

## 7. Maintainer

Project maintained by Sam Siroos.

Repository: https://github.com/samsiroos/ADCheck

Thank you for helping improve ADChecker!