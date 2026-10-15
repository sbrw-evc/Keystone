import { useState } from 'react';
import { LoaderCircle } from 'lucide-react';
import { get, put } from '../api/client';
import type { ProviderConfig, ProviderEntry } from '../api/types';
import { ErrorNotice, Field, Loading, PageHead, PasswordInput, ProviderMark, Switch } from '../components/ui';
import { useT } from '../i18n';
import { isAdmin, useAuth, useLoad } from '../lib/auth';
import { toast } from '../lib/toast';

function ProviderCard({ entry, admin, onSaved }: { entry: ProviderEntry; admin: boolean; onSaved: (all: ProviderEntry[]) => void }) {
  const t = useT();
  const [c, setC] = useState<ProviderConfig>(entry.config);
  const [domains, setDomains] = useState((entry.config.allowed_domains ?? []).join(', '));
  const [secret, setSecret] = useState('');
  const [key, setKey] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const set = (x: Partial<ProviderConfig>) => setC({ ...c, ...x });
  const ro = !admin;
  const title = entry.kind === 'google' ? 'Google' : entry.kind === 'apple' ? 'Apple' : c.title || 'OpenID Connect';
  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      const all = await put<ProviderEntry[]>(`/api/v1/settings/providers/${entry.kind}`, {
        config: { ...c, allowed_domains: domains.split(/[\s,;]+/).filter(Boolean) },
        client_secret: secret,
        private_key: key,
      });
      setSecret('');
      setKey('');
      onSaved(all);
      toast(t('Saved'));
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="card">
      <div className="card-head">
        <div className="cell-main">
          <span className="provider-logo">
            <ProviderMark kind={entry.kind} />
          </span>
          <div>
            <h2>{title}</h2>
            <small>
              {entry.kind === 'google'
                ? t('Google accounts and Google Workspace')
                : entry.kind === 'apple'
                  ? t('Sign in with Apple')
                  : t('Any OpenID Connect provider: Keycloak, Okta, Authentik, ADFS…')}
            </small>
          </div>
        </div>
        <Switch checked={c.enabled} disabled={ro} onChange={(v) => set({ enabled: v })} label={c.enabled ? t('On') : t('Off')} />
      </div>
      <div className="card-body">
        <div className="grid-2">
          {entry.kind === 'oidc' && (
            <>
              <Field label={t('Button title')}>
                <input className="input" value={c.title} disabled={ro} onChange={(e) => set({ title: e.target.value })} placeholder="Keycloak" />
              </Field>
              <Field label={t('Issuer')}>
                <input className="input mono" value={c.issuer} disabled={ro} onChange={(e) => set({ issuer: e.target.value })} placeholder="https://id.example.com/realms/main" />
              </Field>
            </>
          )}
          <Field label={entry.kind === 'apple' ? t('Services ID') : t('Client ID')}>
            <input className="input mono" value={c.client_id} disabled={ro} onChange={(e) => set({ client_id: e.target.value })} />
          </Field>
          {entry.kind === 'apple' ? (
            <>
              <Field label={t('Team ID')}>
                <input className="input mono" value={c.team_id} disabled={ro} onChange={(e) => set({ team_id: e.target.value })} />
              </Field>
              <Field label={t('Key ID')}>
                <input className="input mono" value={c.key_id} disabled={ro} onChange={(e) => set({ key_id: e.target.value })} />
              </Field>
              <Field label={t('Private key (.p8)')} hint={entry.private_key_set ? t('Saved; leave empty to keep it') : undefined}>
                <textarea className="input mono" value={key} disabled={ro} onChange={(e) => setKey(e.target.value)} placeholder="-----BEGIN PRIVATE KEY-----" />
              </Field>
            </>
          ) : (
            <Field label={t('Client secret')} hint={entry.client_secret_set ? t('Saved; leave empty to keep it') : undefined}>
              <PasswordInput value={secret} onChange={setSecret} autoComplete="new-password" placeholder={entry.client_secret_set ? '••••••••' : ''} />
            </Field>
          )}
          <Field label={t('Allowed e-mail domains')} hint={t('Comma-separated, e.g. example.com')}>
            <input className="input" value={domains} disabled={ro} onChange={(e) => setDomains(e.target.value)} placeholder="example.com" />
          </Field>
          {entry.kind === 'oidc' && (
            <>
              <Field label={t('Extra scopes')}>
                <input className="input mono" value={c.scopes} disabled={ro} onChange={(e) => set({ scopes: e.target.value })} placeholder="groups" />
              </Field>
              <Field label={t('Groups claim')} hint={t('SPA takes the groups of the person from this claim (optional)')}>
                <input className="input mono" value={c.groups_claim} disabled={ro} onChange={(e) => set({ groups_claim: e.target.value })} placeholder="groups" />
              </Field>
            </>
          )}
        </div>
        <Switch checked={c.existing_only} disabled={ro} onChange={(v) => set({ existing_only: v })} label={t('Only existing accounts')} hint={t('Only people who already have an SPA account with the same verified e-mail may sign in')} />
        <Field label={t('Redirect URI to register at the provider')}>
          <code style={{ padding: '8px 10px' }}>{entry.redirect_uri}</code>
        </Field>
        <ErrorNotice error={error} />
      </div>
      {admin && (
        <div className="card-foot">
          <button type="button" className="btn btn-primary" onClick={save} disabled={busy}>
            {busy && <LoaderCircle size={16} className="spin" />}
            {t('Save')}
          </button>
        </div>
      )}
    </section>
  );
}

export function ProvidersPage() {
  const t = useT();
  const { account } = useAuth();
  const { data, error, setData } = useLoad(() => get<ProviderEntry[]>('/api/v1/settings/providers'));
  return (
    <>
      <PageHead title={t('Sign-in providers')} subtitle={t('Google, Apple and other OpenID Connect providers on the sign-in page. Microsoft Entra ID is under Directories.')} />
      <ErrorNotice error={error} />
      {!data ? <Loading /> : data.map((e) => <ProviderCard key={e.kind} entry={e} admin={isAdmin(account)} onSaved={setData} />)}
    </>
  );
}
