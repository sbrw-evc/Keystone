import { useEffect, useState, type ReactNode } from 'react';
import { CircleCheck, CircleX, FolderTree, LoaderCircle } from 'lucide-react';
import { get, post, put } from '../api/client';
import type { EntraConfig, EntraReport, EntraSettings, LDAPConfig, LDAPReport, LDAPSettings } from '../api/types';
import { ErrorNotice, Field, Loading, PageHead, PasswordInput, ProviderMark, Segmented, Switch } from '../components/ui';
import { useT } from '../i18n';
import { isAdmin, useAuth, useLoad } from '../lib/auth';
import { toast } from '../lib/toast';

function Result({ ok, error, children }: { ok: boolean; error?: string; children?: ReactNode }) {
  const t = useT();
  return (
    <div className={`notice ${ok ? 'notice-success' : 'notice-error'} test-result`}>
      <b className="row">
        {ok ? <CircleCheck size={16} /> : <CircleX size={16} />}
        {ok ? t('The test passed') : t('The test failed')}
      </b>
      {error && <span>{error}</span>}
      {children}
    </div>
  );
}

function LDAPCard({ admin }: { admin: boolean }) {
  const t = useT();
  const { data, error } = useLoad(() => get<LDAPSettings>('/api/v1/settings/ldap'));
  const [c, setC] = useState<LDAPConfig | null>(null);
  const [bindPw, setBindPw] = useState('');
  const [tu, setTu] = useState('');
  const [tp, setTp] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const [report, setReport] = useState<LDAPReport | null>(null);
  const [saveError, setSaveError] = useState<unknown>(null);
  const [pwSet, setPwSet] = useState(false);
  useEffect(() => {
    if (data) {
      setC(data.config);
      setPwSet(data.bind_password_set);
    }
  }, [data]);
  if (!c) return error ? <ErrorNotice error={error} /> : <Loading />;
  const set = (x: Partial<LDAPConfig>) => setC({ ...c, ...x });
  const ro = !admin;
  const save = async () => {
    setBusy('save');
    setSaveError(null);
    try {
      const r = await put<LDAPSettings>('/api/v1/settings/ldap', { config: c, bind_password: bindPw });
      setC(r.config);
      setPwSet(r.bind_password_set);
      setBindPw('');
      toast(t('Saved'));
    } catch (e) {
      setSaveError(e);
    } finally {
      setBusy(null);
    }
  };
  const test = async () => {
    setBusy('test');
    setReport(null);
    try {
      setReport(await post<LDAPReport>('/api/v1/settings/ldap/test', { config: c, bind_password: bindPw, test_username: tu, test_password: tp }));
    } catch (e) {
      setSaveError(e);
    } finally {
      setBusy(null);
    }
  };
  return (
    <section className="card">
      <div className="card-head">
        <div>
          <h2>
            <FolderTree size={18} />
            {t('Active Directory / LDAP')}
          </h2>
          <p className="muted">{t('People sign in with their directory password; Keystone reads their groups at each sign-in.')}</p>
        </div>
        <Switch checked={c.enabled} disabled={ro} onChange={(v) => set({ enabled: v })} label={c.enabled ? t('On') : t('Off')} />
      </div>
      <div className="card-body">
        <Segmented<LDAPConfig['kind']>
          label={t('Directory')}
          value={c.kind}
          onChange={(k) => set({ kind: k })}
          options={[
            { value: 'ad', label: 'Active Directory' },
            { value: 'openldap', label: 'OpenLDAP' },
          ]}
        />
        <div className="grid-2">
          <Field label={t('Server')} hint="ldaps://dc1.example.com:636">
            <input className="input mono" value={c.url} disabled={ro} onChange={(e) => set({ url: e.target.value })} placeholder="ldaps://dc.example.com" />
          </Field>
          <Field label={t('Base DN')}>
            <input className="input mono" value={c.base_dn} disabled={ro} onChange={(e) => set({ base_dn: e.target.value })} placeholder="DC=example,DC=com" />
          </Field>
          <Field label={t('Service account (bind DN)')}>
            <input className="input mono" value={c.bind_dn} disabled={ro} onChange={(e) => set({ bind_dn: e.target.value })} placeholder="CN=svc-keystone,OU=Service,DC=example,DC=com" />
          </Field>
          <Field label={t('Service account password')} hint={pwSet ? t('Saved; leave empty to keep it') : undefined}>
            <PasswordInput value={bindPw} onChange={setBindPw} autoComplete="new-password" placeholder={pwSet ? '••••••••' : ''} />
          </Field>
          <Field label={t('User filter')} hint={t('{username} is replaced with what the person types')}>
            <input className="input mono" value={c.user_filter} disabled={ro} onChange={(e) => set({ user_filter: e.target.value })} />
          </Field>
          <Field label={t('Administrators group (DN)')} hint={t('Members become Keystone administrators (optional)')}>
            <input className="input mono" value={c.admin_group_dn ?? ''} disabled={ro} onChange={(e) => set({ admin_group_dn: e.target.value })} />
          </Field>
        </div>
        <div className="row" style={{ gap: 24 }}>
          <Switch checked={c.start_tls} disabled={ro} onChange={(v) => set({ start_tls: v })} label="StartTLS" />
          <Switch checked={c.skip_verify} disabled={ro} onChange={(v) => set({ skip_verify: v })} label={t('Skip certificate verification')} hint={t('Only for tests')} />
        </div>
        <details>
          <summary className="link-btn">{t('Attributes')}</summary>
          <div className="grid-3" style={{ marginTop: 12 }}>
            {(['username_attr', 'name_attr', 'email_attr', 'first_name_attr', 'last_name_attr', 'department_attr'] as const).map((k) => (
              <Field key={k} label={<span className="mono">{k}</span>}>
                <input className="input mono" value={c[k] ?? ''} disabled={ro} onChange={(e) => set({ [k]: e.target.value } as Partial<LDAPConfig>)} />
              </Field>
            ))}
          </div>
        </details>
        <div className="card" style={{ boxShadow: 'none', background: 'var(--surface-2)' }}>
          <div className="card-body">
            <strong>{t('Test the connection')}</strong>
            <div className="grid-3">
              <input className="input" placeholder={t('User name (optional)')} value={tu} onChange={(e) => setTu(e.target.value)} />
              <PasswordInput value={tp} onChange={setTp} placeholder={t('Password (optional)')} autoComplete="off" />
              <button type="button" className="btn" onClick={test} disabled={!!busy || !admin}>
                {busy === 'test' && <LoaderCircle size={16} className="spin" />}
                {t('Test')}
              </button>
            </div>
            {report && (
              <Result ok={report.ok} error={report.error}>
                <dl className="kv">
                  <dt>{t('Server')}</dt>
                  <dd>{report.probe.server || '—'}</dd>
                  <dt>TLS</dt>
                  <dd>{report.probe.tls || '—'}</dd>
                  <dt>{t('Base DN')}</dt>
                  <dd>{report.probe.base_dn || '—'}</dd>
                  {report.probe.user && (
                    <>
                      <dt>{t('User')}</dt>
                      <dd>
                        {report.probe.user.name} ({report.probe.user.dn})
                      </dd>
                      <dt>{t('Groups')}</dt>
                      <dd>{report.probe.user.groups?.join('; ') || '—'}</dd>
                    </>
                  )}
                </dl>
              </Result>
            )}
          </div>
        </div>
        <ErrorNotice error={saveError} />
      </div>
      {admin && (
        <div className="card-foot">
          <button type="button" className="btn btn-primary" onClick={save} disabled={!!busy}>
            {busy === 'save' && <LoaderCircle size={16} className="spin" />}
            {t('Save')}
          </button>
        </div>
      )}
    </section>
  );
}

function EntraCard({ admin }: { admin: boolean }) {
  const t = useT();
  const { data, error } = useLoad(() => get<EntraSettings>('/api/v1/settings/entra'));
  const [c, setC] = useState<EntraConfig | null>(null);
  const [secret, setSecret] = useState('');
  const [secretSet, setSecretSet] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [report, setReport] = useState<EntraReport | null>(null);
  const [saveError, setSaveError] = useState<unknown>(null);
  useEffect(() => {
    if (data) {
      setC({ ...data.config, cloud: data.config.cloud || 'global' });
      setSecretSet(data.client_secret_set);
    }
  }, [data]);
  if (!c || !data) return error ? <ErrorNotice error={error} /> : <Loading />;
  const set = (x: Partial<EntraConfig>) => setC({ ...c, ...x });
  const ro = !admin;
  const save = async () => {
    setBusy('save');
    setSaveError(null);
    try {
      const r = await put<EntraSettings>('/api/v1/settings/entra', { config: c, client_secret: secret });
      setC(r.config);
      setSecretSet(r.client_secret_set);
      setSecret('');
      toast(t('Saved'));
    } catch (e) {
      setSaveError(e);
    } finally {
      setBusy(null);
    }
  };
  const test = async () => {
    setBusy('test');
    setReport(null);
    try {
      setReport(await post<EntraReport>('/api/v1/settings/entra/test', { config: c, client_secret: secret }));
    } catch (e) {
      setSaveError(e);
    } finally {
      setBusy(null);
    }
  };
  return (
    <section className="card">
      <div className="card-head">
        <div>
          <h2>
            <ProviderMark kind="entra" />
            Microsoft Entra ID
          </h2>
          <p className="muted">{t('People sign in with their Microsoft work account; Keystone reads their groups from Microsoft Graph.')}</p>
        </div>
        <Switch checked={c.enabled} disabled={ro} onChange={(v) => set({ enabled: v })} label={c.enabled ? t('On') : t('Off')} />
      </div>
      <div className="card-body">
        <div className="grid-2">
          <Field label={t('Cloud')}>
            <select className="input" value={c.cloud} disabled={ro} onChange={(e) => set({ cloud: e.target.value })}>
              {Object.keys(data.clouds)
                .filter((k) => ['global', 'usgov', 'china'].includes(k))
                .map((k) => (
                  <option key={k} value={k}>
                    {k === 'global' ? t('Global') : k === 'usgov' ? 'US Government' : t('China (21Vianet)')}
                  </option>
                ))}
            </select>
          </Field>
          <Field label={t('Tenant ID')}>
            <input className="input mono" value={c.tenant_id} disabled={ro} onChange={(e) => set({ tenant_id: e.target.value })} placeholder="contoso.onmicrosoft.com" />
          </Field>
          <Field label={t('Application (client) ID')}>
            <input className="input mono" value={c.client_id} disabled={ro} onChange={(e) => set({ client_id: e.target.value })} />
          </Field>
          <Field label={t('Client secret')} hint={secretSet ? t('Saved; leave empty to keep it') : undefined}>
            <PasswordInput value={secret} onChange={setSecret} autoComplete="new-password" placeholder={secretSet ? '••••••••' : ''} />
          </Field>
          <Field label={t('Group allowed to sign in (object ID)')} hint={t('Empty — everyone in the tenant')}>
            <input className="input mono" value={c.user_group_id ?? ''} disabled={ro} onChange={(e) => set({ user_group_id: e.target.value })} />
          </Field>
          <Field label={t('Administrators group (object ID)')} hint={t('Members become Keystone administrators (optional)')}>
            <input className="input mono" value={c.admin_group_id ?? ''} disabled={ro} onChange={(e) => set({ admin_group_id: e.target.value })} />
          </Field>
        </div>
        <Field label={t('Redirect URI to register in Entra')}>
          <div className="row">
            <code style={{ flex: 1, padding: '8px 10px' }}>{c.redirect_url}</code>
          </div>
        </Field>
        <div className="row">
          <button type="button" className="btn" onClick={test} disabled={!!busy || !admin}>
            {busy === 'test' && <LoaderCircle size={16} className="spin" />}
            {t('Test')}
          </button>
        </div>
        {report && (
          <Result ok={report.ok} error={report.error}>
            <dl className="kv">
              <dt>{t('Issuer')}</dt>
              <dd>{report.probe.issuer || '—'}</dd>
              <dt>{t('Tenant ID')}</dt>
              <dd>{report.probe.tenant_id || '—'}</dd>
              <dt>{t('Client secret')}</dt>
              <dd>{report.probe.credentials ? t('accepted') : t('not checked')}</dd>
            </dl>
          </Result>
        )}
        <ErrorNotice error={saveError} />
      </div>
      {admin && (
        <div className="card-foot">
          <button type="button" className="btn btn-primary" onClick={save} disabled={!!busy}>
            {busy === 'save' && <LoaderCircle size={16} className="spin" />}
            {t('Save')}
          </button>
        </div>
      )}
    </section>
  );
}

export function DirectoriesPage() {
  const t = useT();
  const { account } = useAuth();
  const admin = isAdmin(account);
  return (
    <>
      <PageHead title={t('Directories')} subtitle={t('Where people and their groups come from. Applications never talk to the directories: Keystone does.')} />
      <LDAPCard admin={admin} />
      <EntraCard admin={admin} />
    </>
  );
}
