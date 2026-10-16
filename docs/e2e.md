# End-to-end check with Umbrella Monitoring

`scripts/e2e-monitoring.mjs` (`make e2e-monitoring`) runs a live SPA together with a real Umbrella Monitoring and
drives the whole connection in Chromium (Playwright), the way an administrator and two people would:

| | what happens | what is checked |
| --- | --- | --- |
| 1 | SPA is built and started on a free port with a fresh database (`spa_e2e`); the administrator signs in and changes the initial password | `/healthz`, the first sign-in |
| 2 | the administrator creates alice and bob and sets **Password policy → Second factor → Required for everyone** | the policy is saved |
| 3 | **Applications → Connect an application**: Umbrella Monitoring at its address, alice → `admin`, bob → `user`; the connection key is read from the wizard | the key (`spa1.…`), the redirect address |
| 4 | Umbrella Monitoring starts with `SPA_CONNECTION_KEY` and `SPA_PUBLIC_URL` (database `um_e2e`) | it is connected; SPA receives its role catalogue (`admin`, `user` and its preset roles) and its first synchronisation |
| 5 | alice and bob open Monitoring, are sent to SPA's sign-in ("Umbrella Monitoring asks you to sign in"), change their first password, set up the authenticator app (the script computes the TOTP codes), see their recovery codes and come back | each is signed in to Monitoring with the role from SPA, bound to SPA |
| 6 | | Monitoring lists both people with their roles; SPA counts two people with access |
| 7 | the administrator disables bob in SPA; alice presses **Settings → SPA → Synchronize now** in Monitoring | bob is disabled in Monitoring and his session ends; alice stays; SPA refuses bob's next sign-in ("This account is disabled") |
| 8 | | SPA's audit log has the connection, the published roles, the second factors, the tokens, the change of bob |

SPA and Monitoring run on two different hosts (`localhost` and `127.0.0.1`), so their cookies are separate as in two
real deployments.

## Running it

```sh
make e2e-monitoring
# or
E2E_POSTGRES=postgres://postgres:postgres@127.0.0.1:55432 node scripts/e2e-monitoring.mjs
```

Needs Go, Node with Playwright (the project's or the global one; Chromium from `PLAYWRIGHT_BROWSERS_PATH`, default
`/opt/pw-browsers`, or `CHROMIUM`), `psql`, `git`, a PostgreSQL server where the user may create databases, and the
Umbrella Monitoring repository next to SPA.

| variable | default | |
| --- | --- | --- |
| `E2E_POSTGRES` | `postgres://postgres:postgres@127.0.0.1:55432` | the PostgreSQL server; `spa_e2e` and `um_e2e` are dropped and created again, and dropped after a passed run |
| `UMBRELLA_MONITORING_DIR` | `../Umbrella-Monitoring` | the repository of Umbrella Monitoring |
| `UMBRELLA_MONITORING_REF` | `HEAD` | the commit of Monitoring to check |
| `UM_WEB_DIST` | — | a built web UI of Monitoring, instead of building the snapshot's (`npm ci`, `npm run build`) |
| `E2E_WORK` | a new temporary directory | builds, the snapshot, `screens/` (screenshots of the steps) and `result.json` |
| `E2E_KEEP` | — | `1` keeps SPA and Monitoring running after a passed run (Ctrl+C stops them) |

The script prints each check (`ok` / `FAIL`), the end of the logs of SPA and Monitoring when something fails, and
exits with 0 or 1.

## How Monitoring runs

The script does not change the Monitoring repository: it takes a snapshot of the commit (`git archive`), copies
`scripts/e2e/monitoring_serve_test.go` into it (`app/backend/cmd/spa-e2e/`) and builds that as a test binary with
the build tag `spae2e`. It runs Monitoring as `cmd/umbrella` does after its setup wizard — the state in PostgreSQL,
the system and preset roles, the migrations, `app.New` with its background work (the SPA schedule: publishing the
catalogue and synchronising at start and every 5 minutes), the built web UI — with one difference: OpenBao is the
fake OpenBao of Monitoring's own tests (`secretstest`), which is why it is a test binary. The connection key comes from
`SPA_CONNECTION_KEY`, as in a deployment.
