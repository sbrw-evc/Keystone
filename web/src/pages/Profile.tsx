import { useState, type FormEvent } from 'react';
import { Fingerprint, KeyRound, LoaderCircle, Monitor, Pencil, Plus, ShieldCheck, Smartphone, Trash2, Usb } from 'lucide-react';
import { del, describeError, get, patch, post } from '../api/client';
import type { Passkey, Session, SignInMethods, TotpSetup, TotpState } from '../api/types';
import { CodeInput, RecoveryCodes, TotpSetupForm } from '../components/totp';
import { Avatar, Confirm, ErrorNotice, Field, Loading, Modal, PageHead, PasswordInput } from '../components/ui';
import { formatAgo, formatDate, useT, type TFn } from '../i18n';
import { useAuth, useLoad } from '../lib/auth';
import { toast, toastError } from '../lib/toast';
import { createCredential, passkeysSupported } from '../lib/webauthn';
import { PolicyRules } from './SignIn';

export function sourceLabel(s: string, t: TFn) {
  const m: Record<string, string> = { local: t('Local account'), ldap: t('Directory (LDAP / AD)'), entra: 'Microsoft Entra ID', google: 'Google', apple: 'Apple', oidc: 'OpenID Connect' };
  return m[s] ?? s;
}

export function methodLabel(m: string, t: TFn) {
  const x: Record<string, string> = { pwd: t('Password'), passkey: t('Passkey'), ldap: t('Directory password'), entra: 'Microsoft', google: 'Google', apple: 'Apple', oidc: 'OpenID Connect' };
  return x[m] ?? m;
}

function browserOf(ua: string) {
  const b = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : ua.split(' ')[0] || '—';
  const os = /Windows/.test(ua) ? 'Windows' : /Mac OS X/.test(ua) ? 'macOS' : /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : /Linux/.test(ua) ? 'Linux' : '';
  return os ? `${b} · ${os}` : b;
}

function ChangePassword() {
  const t = useT();
  const { data: info } = useLoad(() => get<SignInMethods>('/api/v1/auth/methods'));
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [repeat, setRepeat] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (next !== repeat) {
      setError(t('The new passwords do not match'));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await post('/api/v1/auth/password/change', { current, new: next });
      setCurrent('');
      setNext('');
      setRepeat('');
      toast(t('The password is changed. Your other sessions have ended'));
    } catch (err) {
      setError(describeError(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <form className="card" onSubmit={submit}>
      <div className="card-head">
        <h2>
          <KeyRound size={18} />
          {t('Password')}
        </h2>
      </div>
      <div className="card-body">
        {error && <div className="notice notice-error">{error}</div>}
        <div className="grid-3">
          <Field label={t('Current password')}>
            <PasswordInput value={current} onChange={setCurrent} autoComplete="current-password" />
          </Field>
          <Field label={t('New password')}>
            <PasswordInput value={next} onChange={setNext} autoComplete="new-password" />
          </Field>
          <Field label={t('Repeat the new password')}>
            <PasswordInput value={repeat} onChange={setRepeat} autoComplete="new-password" />
          </Field>
        </div>
        {info && <PolicyRules policy={info.password_policy} password={next} />}
      </div>
      <div className="card-foot">
        <button className="btn btn-primary" type="submit" disabled={busy || !current || !next}>
          {busy && <LoaderCircle size={16} className="spin" />}
          {t('Change password')}
        </button>
      </div>
    </form>
  );
}

/** Two-step verification: the authenticator app as the second factor of the password sign-in. */
function TwoStep({ username }: { username: string }) {
  const t = useT();
  const { refresh } = useAuth();
  const { data, error, reload } = useLoad(() => get<TotpState>('/api/v1/me/totp'));
  const [setup, setSetup] = useState<{ code: string } | null>(null);
  const [ask, setAsk] = useState<'disable' | 'codes' | 'replace' | null>(null);
  const [codes, setCodes] = useState<string[] | null>(null);
  const changed = () => {
    reload();
    refresh();
  };
  if (data && !data.available) return null;
  return (
    <section className="card">
      <div className="card-head">
        <div>
          <h2>
            <ShieldCheck size={18} />
            {t('Two-step verification')}
          </h2>
          <p className="muted">{t('After the password SPA asks for a code from an authenticator app on your phone. A passkey sign-in needs no code.')}</p>
        </div>
        {data && !data.enabled && (
          <button type="button" className="btn btn-primary" onClick={() => setSetup({ code: '' })}>
            <Plus size={16} />
            {t('Set up')}
          </button>
        )}
      </div>
      <div className="card-body">
        <ErrorNotice error={error} />
        {!data ? (
          <Loading />
        ) : data.enabled ? (
          <div className="row-between">
            <div className="stack" style={{ gap: 4 }}>
              <div>
                <span className="pill pill-ok">{t('On')}</span> {data.enabled_at && <span className="hint">{t('since {date}', { date: formatDate(data.enabled_at, false) })}</span>}
              </div>
              <span className={`hint ${data.recovery_codes_left <= 2 ? 'error-text' : ''}`}>{t('Recovery codes left: {n}', { n: data.recovery_codes_left })}</span>
              {data.required && <span className="hint">{t('The password policy requires two-step verification for your account.')}</span>}
            </div>
            <div className="row-end">
              <button type="button" className="btn btn-sm" onClick={() => setAsk('replace')}>
                {t('Change the app')}
              </button>
              <button type="button" className="btn btn-sm" onClick={() => setAsk('codes')}>
                {t('New recovery codes')}
              </button>
              {!data.required && (
                <button type="button" className="btn btn-sm btn-danger-soft" onClick={() => setAsk('disable')}>
                  {t('Turn off')}
                </button>
              )}
            </div>
          </div>
        ) : (
          <>
            {data.required && <div className="notice notice-warning">{t('The password policy requires two-step verification for your account. Set it up now; you will be asked to at the next sign-in anyway.')}</div>}
            <p className="muted">{t('Two-step verification is off.')}</p>
          </>
        )}
      </div>
      {setup && (
        <Modal title={t('Set up two-step verification')} onClose={() => setSetup(null)} width={560}>
          <TotpSetupForm
            begin={() => post<TotpSetup>('/api/v1/me/totp/setup', setup.code ? { code: setup.code } : {})}
            confirm={async (code) => {
              const res = await post<{ recovery_codes: string[] }>('/api/v1/me/totp/setup/confirm', { code });
              setSetup(null);
              setCodes(res.recovery_codes);
              toast(t('Two-step verification is on'));
              changed();
            }}
            onCancel={() => setSetup(null)}
            submitLabel={t('Turn on')}
          />
        </Modal>
      )}
      {ask && (
        <AskCode
          title={ask === 'disable' ? t('Turn off two-step verification?') : ask === 'codes' ? t('Make new recovery codes?') : t('Change the authenticator app?')}
          text={
            ask === 'disable'
              ? t('Enter a current code from the app (or a recovery code) to turn it off.')
              : ask === 'codes'
                ? t('The old recovery codes stop working. Enter a current code from the app.')
                : t('Enter a current code from the app you use now; then scan the new QR code.')
          }
          confirm={ask === 'disable' ? t('Turn off') : t('Continue')}
          danger={ask === 'disable'}
          onClose={() => setAsk(null)}
          onConfirm={async (code) => {
            if (ask === 'disable') {
              await post('/api/v1/me/totp/disable', { code });
              toast(t('Two-step verification is off'));
              changed();
            } else if (ask === 'codes') {
              const res = await post<{ recovery_codes: string[] }>('/api/v1/me/totp/recovery-codes', { code });
              setCodes(res.recovery_codes);
              changed();
            } else setSetup({ code });
            setAsk(null);
          }}
        />
      )}
      {codes && (
        <Modal
          title={t('Save your recovery codes')}
          onClose={() => setCodes(null)}
          footer={
            <button type="button" className="btn btn-primary" onClick={() => setCodes(null)}>
              {t('I have saved the codes')}
            </button>
          }
        >
          <RecoveryCodes codes={codes} username={username} />
        </Modal>
      )}
    </section>
  );
}

/** Asks for a current code before an action on the second factor. */
function AskCode({ title, text, confirm, danger, onConfirm, onClose }: { title: string; text: string; confirm: string; danger?: boolean; onConfirm: (code: string) => Promise<void>; onClose: () => void }) {
  const t = useT();
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await onConfirm(code);
    } catch (err) {
      setError(err);
      setBusy(false);
    }
  };
  return (
    <Modal title={title} onClose={onClose} width={440}>
      <form className="stack" style={{ gap: 12 }} onSubmit={submit}>
        <p>{text}</p>
        <Field label={t('Code from the app')}>
          <CodeInput value={code} onChange={setCode} recovery />
        </Field>
        <ErrorNotice error={error} />
        <div className="row-end">
          <button type="button" className="btn" onClick={onClose}>
            {t('Cancel')}
          </button>
          <button type="submit" className={`btn ${danger ? 'btn-danger' : 'btn-primary'}`} disabled={busy || code.trim().length < 6}>
            {busy && <LoaderCircle size={16} className="spin" />}
            {confirm}
          </button>
        </div>
      </form>
    </Modal>
  );
}

const KIND_ICON = { security_key: Usb, phone: Smartphone, device: Fingerprint };

function Passkeys({ enabled }: { enabled: boolean }) {
  const t = useT();
  const { refresh } = useAuth();
  const { data, error, reload } = useLoad(() => get<Passkey[]>('/api/v1/me/passkeys'));
  const [adding, setAdding] = useState(false);
  const [name, setName] = useState('');
  const [rename, setRename] = useState<Passkey | null>(null);
  const [remove, setRemove] = useState<Passkey | null>(null);
  const [busy, setBusy] = useState(false);
  const kinds: Record<Passkey['kind'], string> = { security_key: t('Security key'), phone: t('Phone'), device: t('This device or a synced passkey') };
  const add = async () => {
    setBusy(true);
    try {
      const begun = await post<{ ceremony: string; options: { publicKey: Record<string, unknown> } }>('/api/v1/me/passkeys/begin');
      const credential = await createCredential(begun.options);
      await post('/api/v1/me/passkeys/finish', { ceremony: begun.ceremony, credential, name });
      toast(t('The passkey is added'));
      setAdding(false);
      setName('');
      reload();
      refresh();
    } catch (e) {
      toastError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="card">
      <div className="card-head">
        <div>
          <h2>
            <Fingerprint size={18} />
            {t('Passkeys')}
          </h2>
          <p className="muted">{t('Windows Hello, Touch ID, Face ID, Android or a security key. A passkey sign-in is two-factor by itself.')}</p>
        </div>
        {enabled && (
          <button type="button" className="btn btn-primary" onClick={() => setAdding(true)} disabled={!passkeysSupported()}>
            <Plus size={16} />
            {t('Add a passkey')}
          </button>
        )}
      </div>
      <div className="card-body">
        {!enabled && <div className="notice notice-warning">{t('Passkeys are turned off by the administrator')}</div>}
        <ErrorNotice error={error} />
        {!data ? (
          <Loading />
        ) : data.length === 0 ? (
          <p className="muted">{t('You have no passkeys yet.')}</p>
        ) : (
          <div className="table-card" style={{ boxShadow: 'none' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>{t('Name')}</th>
                  <th>{t('Added')}</th>
                  <th>{t('Last used')}</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {data.map((k) => {
                  const I = KIND_ICON[k.kind] ?? Fingerprint;
                  return (
                    <tr key={k.id}>
                      <td>
                        <div className="cell-main">
                          <span className="provider-logo">
                            <I size={16} />
                          </span>
                          <div>
                            <strong>{k.name}</strong>
                            <small>
                              {kinds[k.kind]}
                              {k.backup_state ? ` · ${t('synced')}` : ''}
                            </small>
                          </div>
                        </div>
                      </td>
                      <td>{formatDate(k.created_at, false)}</td>
                      <td>{k.last_used_at ? formatAgo(k.last_used_at) : t('never')}</td>
                      <td className="right">
                        <button type="button" className="icon-btn" title={t('Rename')} aria-label={t('Rename')} onClick={() => setRename(k)}>
                          <Pencil size={16} />
                        </button>
                        <button type="button" className="icon-btn" title={t('Remove')} aria-label={t('Remove')} onClick={() => setRemove(k)}>
                          <Trash2 size={16} />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
      {adding && (
        <Modal
          title={t('Add a passkey')}
          onClose={() => setAdding(false)}
          footer={
            <>
              <button type="button" className="btn" onClick={() => setAdding(false)}>
                {t('Cancel')}
              </button>
              <button type="button" className="btn btn-primary" onClick={add} disabled={busy}>
                {busy ? <LoaderCircle size={16} className="spin" /> : <Fingerprint size={16} />}
                {t('Continue')}
              </button>
            </>
          }
        >
          <p>{t('Your browser will ask you to confirm with your face, fingerprint, PIN or security key.')}</p>
          <Field label={t('Name')} hint={t('So that you recognise it later, e.g. "Work laptop"')}>
            <input className="input" value={name} maxLength={64} onChange={(e) => setName(e.target.value)} autoFocus />
          </Field>
        </Modal>
      )}
      {rename && <RenamePasskey passkey={rename} onClose={() => setRename(null)} onDone={reload} />}
      {remove && (
        <Confirm
          title={t('Remove the passkey?')}
          text={t('{name} will no longer sign you in.', { name: remove.name })}
          confirm={t('Remove')}
          danger
          onClose={() => setRemove(null)}
          onConfirm={async () => {
            await del(`/api/v1/me/passkeys/${remove.id}`);
            reload();
            refresh();
          }}
        />
      )}
    </section>
  );
}

function RenamePasskey({ passkey, onClose, onDone }: { passkey: Passkey; onClose: () => void; onDone: () => void }) {
  const t = useT();
  const [name, setName] = useState(passkey.name);
  const [error, setError] = useState<unknown>(null);
  return (
    <Modal
      title={t('Rename the passkey')}
      onClose={onClose}
      width={420}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            {t('Cancel')}
          </button>
          <button
            type="button"
            className="btn btn-primary"
            onClick={async () => {
              try {
                await patch(`/api/v1/me/passkeys/${passkey.id}`, { name });
                onDone();
                onClose();
              } catch (e) {
                setError(e);
              }
            }}
          >
            {t('Save')}
          </button>
        </>
      }
    >
      <Field label={t('Name')}>
        <input className="input" value={name} maxLength={64} onChange={(e) => setName(e.target.value)} autoFocus />
      </Field>
      <ErrorNotice error={error} />
    </Modal>
  );
}

function Sessions() {
  const t = useT();
  const { data, error, reload } = useLoad(() => get<Session[]>('/api/v1/me/sessions'));
  const others = data?.filter((s) => !s.current) ?? [];
  return (
    <section className="card">
      <div className="card-head">
        <div>
          <h2>
            <Monitor size={18} />
            {t('Sessions')}
          </h2>
          <p className="muted">{t('Where you are signed in to SPA. Ending a session signs that browser out.')}</p>
        </div>
        {others.length > 0 && (
          <button
            type="button"
            className="btn btn-danger-soft"
            onClick={async () => {
              try {
                for (const s of others) await del(`/api/v1/me/sessions/${s.id}`);
                reload();
              } catch (e) {
                toastError(e);
              }
            }}
          >
            {t('End all other sessions')}
          </button>
        )}
      </div>
      <div className="card-body">
        <ErrorNotice error={error} />
        {!data ? (
          <Loading />
        ) : (
          <div className="table-card" style={{ boxShadow: 'none' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>{t('Browser')}</th>
                  <th>{t('Signed in with')}</th>
                  <th>{t('Address')}</th>
                  <th>{t('Started')}</th>
                  <th>{t('Last active')}</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {data.map((s) => (
                  <tr key={s.id}>
                    <td>
                      <strong>{browserOf(s.user_agent)}</strong> {s.current && <span className="pill pill-ok">{t('this session')}</span>}
                    </td>
                    <td>
                      {methodLabel(s.method, t)} {s.mfa && <span className="pill pill-info">MFA</span>}
                    </td>
                    <td className="mono">{s.ip}</td>
                    <td>{formatDate(s.created_at)}</td>
                    <td>{formatAgo(s.last_seen_at)}</td>
                    <td className="right">
                      {!s.current && (
                        <button
                          type="button"
                          className="btn btn-sm btn-danger-soft"
                          onClick={async () => {
                            try {
                              await del(`/api/v1/me/sessions/${s.id}`);
                              reload();
                            } catch (e) {
                              toastError(e);
                            }
                          }}
                        >
                          {t('End')}
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  );
}

export function ProfilePage() {
  const t = useT();
  const { account } = useAuth();
  if (!account) return null;
  const name = account.name || account.username;
  return (
    <>
      <PageHead title={t('Account and security')} subtitle={t('Your password, two-step verification, passkeys and sessions — for every Umbrella application.')} />
      <section className="card card-pad">
        <div className="row-between">
          <div className="cell-main">
            <Avatar name={name} size={48} />
            <div>
              <strong style={{ fontSize: 16 }}>{name}</strong>
              <small>
                {account.username}
                {account.email ? ` · ${account.email}` : ''}
              </small>
            </div>
          </div>
          <div className="chips">
            <span className="pill">{sourceLabel(account.source, t)}</span>
            {account.groups.map((g) => (
              <span key={g} className="pill pill-accent">
                {g}
              </span>
            ))}
          </div>
        </div>
        {account.password_expires_at && (
          <p className={`hint ${account.password_expires_soon ? 'error-text' : ''}`} style={{ marginTop: 12 }}>
            {t('The password expires on {date}.', { date: formatDate(account.password_expires_at, false) })}
          </p>
        )}
      </section>
      {account.source === 'local' ? (
        <ChangePassword />
      ) : (
        <div className="notice">{t('Your password is managed by {source}.', { source: sourceLabel(account.source, t) })}</div>
      )}
      <TwoStep username={account.username} />
      <Passkeys enabled={account.passkeys_enabled} />
      <Sessions />
    </>
  );
}
