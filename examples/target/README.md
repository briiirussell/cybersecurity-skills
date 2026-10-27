# notes-api (deliberately vulnerable)

**Do not deploy this.** It's a small Express notes API with planted bugs, written as the target for the worked examples in [`examples/`](../README.md). It isn't meant to run in production, and some of its dependencies are pinned to versions with known advisories on purpose.

- Users sign up, log in and get a JWT.
- Notes belong to a user and can be read, edited, searched and shared.
- `POST /api/preview` fetches a URL to build a link preview.
- `/api/admin/*` is for admins.

The planted bugs aren't listed here, so a run against this app can't read the answers. They're in the examples' reports.
