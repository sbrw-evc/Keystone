// The JSON of Keystone's /api/v1 (backend/internal/app). Times are RFC 3339 strings.

export interface Method {
  id: string;
  title: string;
}

export interface PasswordPolicy {
  min_length: number;
  require_digits: boolean;
  min_digits: number;
  require_special: boolean;
  min_special: number;
  require_mixed_case: boolean;
  letters: 'latin' | 'cyrillic' | 'latin_cyrillic' | 'any';
  max_age_days: number;
  warn_days: number;
  history_count: number;
  block_common: boolean;
  lockout_attempts: number;
  lockout_minutes: number;
  /** Who must use an authenticator app after a password. */
  second_factor: 'optional' | 'admins' | 'everyone';
}

export interface SignInMethods {
  organization: string;
  methods: Method[];
  password_policy: PasswordPolicy;
}

export interface AppLauncher {
  id: string;
  name: string;
  type: AppType;
  url: string;
  roles: string[];
}

export type SPARole = 'admin' | 'auditor' | 'user';

export interface Account {
  id: string;
  username: string;
  name: string;
  email: string;
  source: string;
  spa_role: SPARole;
  must_change: boolean;
  password_expires_at?: string;
  password_expires_soon: boolean;
  passkeys: number;
  passkeys_enabled: boolean;
  groups: string[];
  applications: AppLauncher[];
  session_method: string;
  totp: boolean;
  totp_required: boolean;
}

export interface SignedIn {
  user: Account;
  next: string;
  /** Recovery codes of an authenticator app set up during this sign-in (shown once). */
  recovery_codes?: string[];
}

export interface TotpState {
  enabled: boolean;
  enabled_at?: string;
  recovery_codes_left: number;
  available: boolean;
  required: boolean;
}

export interface TotpSetup {
  secret: string;
  uri: string;
  qr: string;
}

export interface Passkey {
  id: string;
  name: string;
  transports: string[] | null;
  backup_eligible: boolean;
  backup_state: boolean;
  created_at: string;
  last_used_at?: string;
  kind: 'security_key' | 'phone' | 'device';
}

export interface Session {
  id: string;
  method: string;
  mfa: boolean;
  ip: string;
  user_agent: string;
  created_at: string;
  last_seen_at: string;
  expires_at: string;
  current: boolean;
}

export interface Step {
  id: 'public_url' | 'policy' | 'passkey' | 'directory' | 'application' | 'roles' | 'second_admin';
  done: boolean;
  optional: boolean;
  path: string;
}

export interface Onboarding {
  done: boolean;
  steps: Step[];
}

export interface User {
  id: string;
  username: string;
  email: string;
  name: string;
  source: string;
  password_changed_at?: string;
  must_change: boolean;
  disabled: boolean;
  spa_role: SPARole;
  locked_until?: string;
  last_sign_in_at?: string;
  created_at: string;
  updated_at: string;
  groups: string[];
  passkeys: number;
  totp: boolean;
  locked: boolean;
  app_roles: Record<string, string[]>;
  password_expires_at?: string;
}

export interface UserInput {
  username: string;
  name: string;
  email: string;
  spa_role: SPARole;
  disabled: boolean;
  password?: string;
  groups?: string[];
}

export interface Group {
  id: string;
  name: string;
  description: string;
  source: 'local' | 'ldap' | 'entra' | string;
  external_id?: string;
  members: number;
  created_at: string;
}

export interface GroupDetail extends Group {
  member_ids: string[];
}

export interface GroupInput {
  name: string;
  description: string;
  members?: string[];
  source?: string;
  external_id?: string;
}

// The type IDs follow the product names of the Umbrella family; the server maps the IDs used before the rename
// (umbrella-monitoring, inventory-db, umbrella-flow) to these.
export type AppType = 'beacon' | 'current' | 'ledger' | 'network-control' | 'oidc';

export interface Role {
  id: string;
  name: string;
  description?: string;
}

export interface Assignment {
  id?: number;
  app_id?: string;
  subject_type: 'user' | 'group';
  subject_id: string;
  subject_name?: string;
  role: string;
}

export interface Application {
  id: string;
  type: AppType;
  name: string;
  base_url: string;
  redirect_uris: string[] | null;
  logout_uris: string[] | null;
  client_id: string;
  roles: Role[];
  default_role: string;
  roles_published?: string;
  last_sync_at?: string;
  user_import_until?: string;
  created_at: string;
  updated_at: string;
  users: number;
  assignments: Assignment[];
  callback: string;
}

export interface ApplicationList {
  applications: Application[];
  types: Record<AppType, string>;
  presets: Record<AppType, Role[]>;
}

export interface AppInput {
  type: AppType;
  name: string;
  base_url: string;
  redirect_uris?: string[];
  logout_uris?: string[];
  roles?: Role[];
  default_role?: string;
  assignments?: Assignment[];
}

export interface Connection {
  application: Application;
  key: string;
}

export interface PolicySummary {
  policy: PasswordPolicy;
  local_users: number;
  expired_users: number;
  expiring_users: number;
  locked_users: number;
}

export interface General {
  general: { organization: string; allow_local: boolean; public_url: string; trusted_proxies: string[]; session_hours: number };
  passkeys: { enabled: boolean; rp_id: string };
  issuer: string;
  secrets: string;
  public_url_set: boolean;
  proxy_hint?: string;
}

export interface LDAPConfig {
  enabled: boolean;
  kind: 'ad' | 'openldap';
  url: string;
  start_tls: boolean;
  skip_verify: boolean;
  ca_cert?: string;
  bind_dn: string;
  base_dn: string;
  user_filter: string;
  username_attr: string;
  name_attr: string;
  email_attr: string;
  first_name_attr: string;
  last_name_attr: string;
  middle_name_attr: string;
  title_attr: string;
  department_attr: string;
  manager_attr: string;
  photo_attr: string;
  admin_group_dn?: string;
}

export interface LDAPSettings {
  config: LDAPConfig;
  bind_password_set: boolean;
}

export interface LDAPReport {
  ok: boolean;
  error?: string;
  probe: {
    server: string;
    tls: string;
    base_dn: string;
    admin_group: boolean;
    user_authenticated: boolean;
    user?: { dn: string; username: string; name: string; email?: string; groups?: string[]; groups_known: boolean; groups_error?: string; admin: boolean };
  };
}

export interface EntraConfig {
  enabled: boolean;
  cloud: string;
  tenant_id: string;
  client_id: string;
  redirect_url: string;
  admin_group_id?: string;
  user_group_id?: string;
}

export interface EntraSettings {
  config: EntraConfig;
  client_secret_set: boolean;
  clouds: Record<string, { Login: string; Graph: string }>;
}

export interface EntraReport {
  ok: boolean;
  error?: string;
  probe: { issuer?: string; tenant_id?: string; credentials: boolean };
}

export interface ProviderConfig {
  enabled: boolean;
  title: string;
  issuer: string;
  client_id: string;
  team_id: string;
  key_id: string;
  allowed_domains: string[] | null;
  existing_only: boolean;
  scopes: string;
  groups_claim: string;
}

export interface ProviderEntry {
  kind: 'google' | 'apple' | 'oidc';
  config: ProviderConfig;
  client_secret_set: boolean;
  private_key_set: boolean;
  redirect_uri: string;
}

export interface AuditEntry {
  id: number;
  at: string;
  actor: string;
  action: string;
  target: string;
  detail: Record<string, unknown> | null;
  ip: string;
}
