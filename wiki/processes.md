# Keystone: business processes

Keystone is where people of the Umbrella family sign in and where their access is decided. How the applications use
it is in [family.md](https://github.com/sbrw-evc/current/blob/HEAD/docs/family.md) and the wire protocol in [protocol.md](protocol.md); this page is about the
processes inside Keystone.

## Roles in the processes

| Who | Keystone role | Does |
| --- | --- | --- |
| Administrator | `admin` | people, groups, applications, policy, directories, providers |
| Auditor | `auditor` | reads everything, changes nothing |
| Person | none | signs in, manages their own passkeys, second factor and sessions |
| Application | connection key | reads people, publishes its roles |

## K1. Install

1. The administrator sets the master key, the first administrator's password and the public address, and runs
   `docker compose up`.
2. The first administrator signs in and changes the password at once.
3. "First steps" leads through the password policy, a passkey, a directory and the first application.

## K2. Connect an application

1. The administrator picks the application type (Beacon, Ledger, Current, Network Control or any OpenID Connect
   application) and its address.
2. They set role rules: a person or a group gets a role in that application.
3. Keystone shows the connection key once and keeps only its hash.
4. The application connects, publishes its own role catalogue and replaces the placeholder roles.
5. A lost key is reissued; the old key stops working at once.

## K3. Sign a person in

1. An application sends the person to Keystone (OpenID Connect, PKCE required).
2. Keystone signs them in by an allowed method: password under the policy, LDAP / Active Directory, passkey,
   Microsoft Entra ID, Google, Apple or another OpenID Connect provider.
3. Where the policy requires it, the person enters an authenticator-app code or a recovery code; a person who must
   have a second factor and has none sets it up before the session starts.
4. Keystone checks the person has a role in that application; without one the application gets `access_denied`.
5. The application gets an ID token with the roles, groups and sign-in methods.

## K4. Manage people and groups

1. People come from local accounts, directories and providers; groups are local or point to directory groups.
2. The administrator creates people, resets passwords, unlocks accounts, removes lost passkeys or second factors and
   ends sessions.
3. Disabling a person ends their access in every application at the next synchronization (5 minutes).

## K5. Policy and lifecycle

1. The password policy sets length, complexity, expiry, history, lockout and who must have a second factor.
2. Expired passwords are changed at sign-in; repeated failures lock the account for the policy's time.
3. Signing keys are rotated; applications accept the current and the previous key.

## K6. Audit

1. Every sign-in, failure, lockout, change of a person, group, application, rule or setting is in the audit log.
2. Auditors read it; nobody can change it from the interface.
