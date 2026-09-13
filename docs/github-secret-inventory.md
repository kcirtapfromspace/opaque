# List GitHub secret metadata

`github.list_secrets` returns secret names and creation/update timestamps. It
never reads secret values. Supply a GitHub token reference with read permission
for the selected scope, and authorize the operation in broker policy:

```json
{
  "scope": "actions",
  "repo": "owner/repository",
  "github_token_ref": "keychain:opaque/github-token"
}
```

The same complete-list behavior applies to repository Actions, environment
Actions, user Codespaces, repository Codespaces, Dependabot, and organization
Actions secrets. The API requests 100 entries per page and returns success only
after collecting the declared number of distinct secret names.

Enumeration is bounded to 100 pages (10,000 secrets), 512 KiB per response page,
8 MiB across response pages, and 60 seconds for the whole inventory. Exceeded
bounds, count changes, repeated names, malformed responses, incomplete pages,
and errors on later pages fail the operation without returning a partial list.
Each numbered request uses the configured GitHub API endpoint and original
scope. Pagination links and redirects cannot change the request destination.

GitHub does not supply snapshot isolation for this API. Avoid concurrent secret
creation/deletion when reconciling inventories: changes that preserve the total
count can evade drift detection. A successful enumeration is metadata observed
over the request interval, not an atomic snapshot.

This behavior is implemented in source; installation depends on the release
containing it. Local protocol tests cover every supported scope and pagination
failure. Live account acceptance remains a separate deployment check.

Vendor references: [Actions secrets](https://docs.github.com/en/rest/actions/secrets),
[Codespaces user secrets](https://docs.github.com/en/rest/codespaces/secrets),
[Codespaces organization and repository secrets](https://docs.github.com/en/rest/codespaces/organization-secrets),
and [Dependabot secrets](https://docs.github.com/en/rest/dependabot/secrets).
